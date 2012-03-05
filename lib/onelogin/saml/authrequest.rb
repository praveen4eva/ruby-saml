#require "base64"
#require "uuid"
#require "zlib"
#require "cgi"

module Onelogin::Saml
  class Authrequest
    def create(settings, params = {})
      request_params = "RPID=" + settings.relying_party_identifier + "&TARGET=" + settings.assertion_consumer_service_url
      settings.idp_sso_target_url + request_params
    end
  end
end
