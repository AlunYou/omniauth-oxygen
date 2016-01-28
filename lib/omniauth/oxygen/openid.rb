require 'openid'
require 'openid/extensions/ui'
require 'omniauth/oxygen/register'
require 'omniauth/oxygen/iframe_ui'

OpenID::Util.logger = Rails.logger

module Rack
  class OpenID
    private
    def begin_authentication(env, qs)
      req = Rack::Request.new(env)
      params = self.class.parse_header(qs)
      session = env["rack.session"]

      unless session
        raise RuntimeError, "Rack::OpenID requires a session"
      end

      consumer   = ::OpenID::Consumer.new(session, @store)
      identifier = params['identifier'] || params['identity']
      immediate  = params['immediate'] == 'true'

      begin
        oidreq = consumer.begin(identifier)
        add_simple_registration_fields(oidreq, params)
        add_attribute_exchange_fields(oidreq, params)
        add_oauth_fields(oidreq, params)
        add_ui_field(req,oidreq, params)
        if env['rack.request.query_hash'] && env['rack.request.query_hash']['register'] == 'true'
          add_register_field(oidreq, params)
        end
        url = open_id_redirect_url(req, oidreq, params["trust_root"], params["return_to"], params["method"], immediate)
        return redirect_to(url)
      rescue ::OpenID::OpenIDError, Timeout::Error => e
        env[RESPONSE] = MissingResponse.new
        return @app.call(env)
      end
    end

    def add_ui_field(req, oidreq, fields)
      host_name = ENV['APP_URL']
      refresh_url = req.scheme + '://' + req.host_with_port + '/loginiframe_refresh.htm'
      uireq = ::OpenID::UI::IFrameRequest.new(refresh_url, "iframe")
      oidreq.add_extension(uireq)
    end

    def add_register_field(oidreq, fields)
      regreq = ::OpenID::Register::Request.new()
      oidreq.add_extension(regreq)
    end
    def add_oauth_fields(oidreq, fields)
      if (consumer = fields['oauth[consumer]'])
        oauthreq = ::OpenID::OAuth::Request.new(consumer)
        oidreq.add_extension(oauthreq)
      end
    end
  end
end