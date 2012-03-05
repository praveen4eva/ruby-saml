module Onelogin::Saml
  class Settings
    attr_accessor :assertion_consumer_service_url, :issuer, :relying_party_identifier
    attr_accessor :idp_sso_target_url, :idp_cert_fingerprint, :name_identifier_format
    attr_accessor :idp_confirmation_method, :asserting_party_id, :referer_url, :groups
  end
end
