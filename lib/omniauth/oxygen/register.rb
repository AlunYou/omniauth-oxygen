# An implementation of the OpenID Autodesk register extension

require 'openid/extension'

module OpenID

  module Register
    NS_URI = "http://autodesk.com/openid/ext/register/1.0"
    REGISTER_MODE_KEY = "mode"
    REGISTER_MODE_REGISTER = "register"
    class Request < Extension
      attr_accessor :mode, :ns_alias, :ns_uri
      def initialize(mode = nil, icon = nil, lang = nil)
        @ns_alias = 'register'
        @ns_uri = NS_URI
        @mode = mode || REGISTER_MODE_REGISTER
      end

      def get_extension_args
        ns_args = {}
        ns_args['mode'] = @mode if @mode
        return ns_args
      end
      def self.from_openid_request(oid_req)
        ui_req = new
        args = oid_req.message.get_args(NS_URI)
        if args == {}
          return nil
        end
        ui_req.parse_extension_args(args)
        return ui_req
      end
      def parse_extension_args(args)
        @mode = args["mode"]
      end

    end

  end

end
