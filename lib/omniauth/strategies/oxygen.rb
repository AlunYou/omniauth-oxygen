# encoding: utf-8
require 'omniauth'
require 'rack/openid'
require 'openid/store/memory'

require 'oauth'
require 'oauth/consumer'
require 'oauth/token'
require 'oauth/tokens/access_token'
require 'oauth/client/helper'

# override the oauth params oxygen support
module OAuth
  module Client
    # override to only pass oxygen supported params
    class Helper
      def oauth_parameters
        {
            # oxygen doesn't support these three
            # 'oauth_body_hash'        => options[:body_hash],
            # 'oauth_callback'         => options[:oauth_callback],
            'oauth_verifier' => options[:oauth_verifier],
            'oauth_consumer_key' => options[:consumer].key,
            'oauth_token' => options[:token] ? options[:token].token : '',
            'oauth_signature_method' => options[:signature_method],
            'oauth_timestamp' => timestamp,
            'oauth_nonce' => nonce,
            'oauth_version' => (options[:oauth_version] || '1.0'),
            # this only has value and is only useful when refresh token.
            # according to https://wiki.autodesk.com/display/saascore/OAuth+Token+Expiry, the access_token expires
            # in two days, so currently no need to implement refresh mechanism.
            'oauth_session_handle' => options[:oauth_session_handle]
        }.reject { |_k, v| v.nil? } # v.to_s == "" }
      end
    end
  end
end

module OmniAuth
  module Strategies
    class Oxygen
      include OmniAuth::Strategy

      AX = {
          :email => 'http://axschema.org/contact/email',
          :name => 'http://axschema.org/namePerson',
          :nickname => 'http://axschema.org/namePerson/friendly',
          :first_name => 'http://axschema.org/namePerson/first',
          :last_name => 'http://axschema.org/namePerson/last',
          :uid => "http://axschema.org/autodesk/userid",
          :image20 => "http://axschema.org/autodesk/media/image/20",
          :image50 => "http://axschema.org/autodesk/media/image/50"
      }

      option :env, :staging
      option :required, [AX[:email], AX[:name], AX[:first_name], AX[:last_name], 'email', 'fullname', AX[:uid], AX[:image20], AX[:image50]]
      option :optional, [AX[:nickname], 'nickname']
      option :store, ::OpenID::Store::Memory.new
      option :identifier, nil
      option :identifier_param, 'openid_url'
      option :logout, '/auth/oxygen'
      option :register, '/auth/oxygen?register=true'
      option :access_token_path, '/OAuth/AccessToken'

      def request_phase
        openid = Rack::OpenID.new(dummy_app, options[:store])
        # check if try the immediate mode
        req = Rack::Request.new(env)
        @immediate = req.params['immediate']
        @app_return_url_encoded = ERB::Util.url_encode(req.params['app_return_url'])

        response = openid.call(env)
        case env['rack.openid.response']
          when Rack::OpenID::MissingResponse, Rack::OpenID::TimeoutResponse
            fail!(:connection_failed)
          else
            response
        end
      end

      def callback_phase
        return fail!(:invalid_credentials) unless openid_response && openid_response.status == :success
        super
      end

      def other_phase
        if on_path?("/auth/logout")
          @env['omniauth.strategy'] ||= self
          setup_phase
          [302, {'Content-Type' => 'text', 'Location' => logout_url}, ['302 found']]
        else
          call_app!
        end
      end

      uid { oxygen_info['uid'] }

      info do
        oxygen_info
      end

      def credentials
        oauth_credentials
      end

      extra do
        {}
      end

      private

      def dummy_app
        lambda { |env| [401, {"WWW-Authenticate" => Rack::OpenID.build_header(
                               :identifier => identifier,
                               :return_to => callback_url,
                               :required => options.required,
                               :optional => options.optional,
                               :"oauth[consumer]" => options.consumer_key,
                               :method => 'post',
                               :immediate => @immediate,
                               :app_return_url => @app_return_url_encoded
                           )}, []] }
      end

      def identifier
        i = options.identifier || request.params[options.identifier_param.to_s]

        if i.nil? or i == ''
          i = case options.env
                when "dev"
                  "https://accounts-dev.autodesk.com"
                when "production"
                  "https://accounts.autodesk.com"
                else
                  "https://accounts-staging.autodesk.com"
              end
        end
        i
      end

      def logout_url
        "#{identifier}/Authentication/LogOut?ReturnToUrl=#{full_host}#{logout_return_url}"
      end

      def logout_return_url
        options[:logout] ||= '/auth/oxygen'
      end

      def openid_response
        unless @openid_response
          openid = Rack::OpenID.new(lambda { |env| [200, {}, []] }, options[:store])
          openid.call(env)
          @openid_response = env.delete('rack.openid.response')
        end
        @openid_response
      end

      def sreg_user_info
        sreg = ::OpenID::SReg::Response.from_success_response(openid_response)
        return {} unless sreg
        {
            'email' => sreg['email'],
            'name' => sreg['fullname'],
            'location' => sreg['postcode'],
            'nickname' => sreg['nickname']
        }.reject { |k, v| v.nil? || v == '' }
      end

      def ax_user_info
        ax = ::OpenID::AX::FetchResponse.from_success_response(openid_response)
        return {} unless ax
        {
            'email' => ax.get_single(AX[:email]),
            'first_name' => ax.get_single(AX[:first_name]),
            'last_name' => ax.get_single(AX[:last_name]),
            'name' => (ax.get_single(AX[:name]) || [ax.get_single(AX[:first_name]), ax.get_single(AX[:last_name])].join(' ')).strip,
            'nickname' => ax.get_single(AX[:nickname]),
            'uid' => ax.get_single(AX[:uid]),
            'profile20' => ax.get_single(AX[:image20]),
            'profile50' => ax.get_single(AX[:image50])
        }.inject({}) { |h, (k, v)| h[k] = Array(v).first; h }.reject { |k, v| v.nil? || v == '' }
      end

      def oxygen_info
        @oxygen_info ||= sreg_user_info.merge(ax_user_info)
      end

      # below are for oauth2 strategy
      # openid + oauth hybrid authentication docs:
      # http://step2.googlecode.com/svn/spec/openid_oauth_extension/latest/openid_oauth_extension.html
      # oxygen api docs: https://wiki.autodesk.com/pages/viewpage.action?pageId=42437358
      # oauth errors: https://wiki.autodesk.com/display/saascore/OAuth+Problem+Error+codes
      def oauth_credentials
        return @oauth_credentials if @oauth_credentials

        oauth_response = ::OpenID::OAuth::Response.from_success_response(@openid_response)
        consumer = ::OAuth::Consumer.new(
            options.consumer_key,
            options.consumer_secret,
            site: identifier,
            access_token_path: options.access_token_path
        )

        # OAuth request token secret is also blank in OpenID/OAuth Hybrid
        request_token = ::OAuth::RequestToken.new(consumer, oauth_response.request_token, '')
        @access_token = request_token.get_access_token
        @oauth_credentials = { 'oxygen_access_token' => @access_token.token,
                               'oxygen_access_secret' => @access_token.secret }
      rescue => e
        # rescue so that even when fail to get oauth token, the login feature will not be affected
        @oauth_credentials = { 'oxygen_access_token' => nil,
                               'oxygen_access_secret' => nil }
      end
    end
  end
end
