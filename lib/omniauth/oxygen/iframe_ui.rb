# An implementation of the OpenID User Interface Extension 1.0 - DRAFT 0.5
# see: http://svn.openid.net/repos/specifications/user_interface/1.0/trunk/openid-user-interface-extension-1_0.html

require 'openid/extension'

module OpenID

  module UI
    UI_IFRAME_REFRESH_KEY = "iframe_refresh_url";

    class IFrameRequest < ::OpenID::UI::Request
      attr_accessor :lang, :icon, :mode, :ns_alias, :ns_uri
      def initialize(refresh_url,mode )
        @ns_alias = 'ui'
        @ns_uri = NS_URI
        @refresh_url = refresh_url
        super(mode)
      end

      def get_extension_args
        ns_args = {}
        ns_args['lang'] = @lang if @lang
        ns_args['icon'] = @icon if @icon
        ns_args['mode'] = @mode if @mode
        ns_args[UI_IFRAME_REFRESH_KEY] = @refresh_url if @refresh_url
        return ns_args
      end

      # Instantiate a Request object from the arguments in a
      # checkid_* OpenID message
      # return nil if the extension was not requested.
      def self.from_openid_request(oid_req)
        ui_req = new
        args = oid_req.message.get_args(NS_URI)
        if args == {}
          return nil
        end
        ui_req.parse_extension_args(args)
        return ui_req
      end

      # Set UI extension parameters
      def parse_extension_args(args)
        @lang = args["lang"]
        @icon = args["icon"]
        @mode = args["mode"]
        @refresh_url = args[UI_IFRAME_REFRESH_KEY]
      end

    end

  end

end
