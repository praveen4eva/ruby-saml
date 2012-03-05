require "xml_security"
require "time"

module Onelogin::Saml
  class Response

    ASSERTION = "urn:oasis:names:tc:SAML:1.0:assertion"
    PROTOCOL  = "urn:oasis:names:tc:SAML:1.0:protocol"
    DSIG      = "http://www.w3.org/2000/09/xmldsig#"

    attr_accessor :response, :document, :logger, :settings, :original

    def initialize(response)
      raise SA1013Exception if response.nil?
      self.response                 = response
      self.document                 = XMLSecurity::SignedDocument.new(Base64.decode64(response))
    end

    def is_valid?
      # Check Validity of Signature
      return false unless document.validate(settings.idp_cert_fingerprint, logger)

      # Check Groups
      return false unless groups_valid?

      # Check Token Expiry
      return false if token_expired?

      # Check Validity of User Principle
      return false unless valid_user_principal?

      # Check Validity of Recipient URL
      return false unless valid_recipient_url?

      # Check Validity of Issuer
      return false unless valid_issuer?

      # Check Validity of Confirmation Method
      return false unless valid_confirmation_method?

      # Return true otherwise
      true
    end

    # Checks For Group Authorization
    def groups_valid?
      begin
        response_groups = []
        authorized_groups = settings.groups
        raise SA1009Exception if authorized_groups.blank?
        attribute_element = REXML::XPath.first(document,"/p:Response/a:Assertion/a:AttributeStatement/a:Attribute", { "p" => PROTOCOL, "a" => ASSERTION })
        REXML::XPath.each(attribute_element, "a:AttributeValue", { "a" => ASSERTION }) do | attribute |
          response_groups << attribute.text
        end
        for group in authorized_groups
          raise SA1009Exception unless response_groups.include?(group)
        end
      rescue SA1009Exception => exp
        Rails.logger.error "#{exp.class} - #{exp.message}"
        return false
      else
        return true
      end
    end

    # Checks Token Expiry - Returns true if token has expired, false if still valid.
    def token_expired?
      begin
        conditions_element = REXML::XPath.first(document,"/p:Response/a:Assertion/a:Conditions", { "p" => PROTOCOL, "a" => ASSERTION })
        raise SA1012Exception if conditions_element.nil?
        raise SA1003Exception if conditions_element.attribute('NotBefore') and Time.now.utc < Time.parse(conditions_element.attribute('NotBefore').value)
        raise SA1004Exception if conditions_element.attribute('NotOnOrAfter') and Time.now.utc >= Time.parse(conditions_element.attribute('NotOnOrAfter').value)
      rescue RuntimeError => exp
        Rails.logger.error "#{exp.class} - #{exp.message}"
        return true
      else
        return false
      end
    end

    # Checks presence and validity of the User Principle - Returns true if valid, false otherwise.
    def valid_user_principal?
      begin
        user_principal  = REXML::XPath.first(document, "/p:Response/a:Assertion/a:AuthenticationStatement/a:Subject/a:NameIdentifier", { "p" => PROTOCOL, "a" => ASSERTION })
        raise SA1006Exception unless user_principal
        user_principal = user_principal.text
        raise SA1006Exception if user_principal.empty?
      rescue RuntimeError => exp
        Rails.logger.error "#{exp.class} - #{exp.message}"
        return false
      else
      end
      
      true
    end

    # Checks presence and validity of the Recipient URL - Returns true if valid, false otherwise.
    def valid_recipient_url?
      begin
        response_object = REXML::XPath.first(document, "/p:Response", { "p" => PROTOCOL })
        recipient = response_object.attribute('Recipient').value
        raise SA1005Exception unless recipient == settings.assertion_consumer_service_url
      rescue RuntimeError => exp
        Rails.logger.error "#{exp.class} - #{exp.message}"
        return false
      else
        return true
      end
    end

    # Checks presence and validity of the Issuer - Returns true if valid, false otherwise.
    def valid_issuer?
      begin
        assertion = REXML::XPath.first(document, "/p:Response/a:Assertion", { "p" => PROTOCOL, "a" => ASSERTION })
        issuer = assertion.attribute('Issuer').value
        raise SA1008Exception unless issuer == settings.issuer
      rescue RuntimeError => exp
        Rails.logger.error "#{exp.class} - #{exp.message}"
        return false
      else
        return true
      end
    end

    # Checks presence and validity of the Confirmation Method - Returns true if valid, false otherwise.
    def valid_confirmation_method?
      begin
      confirmation_method  = REXML::XPath.first(document, "/p:Response/a:Assertion/a:AuthenticationStatement/a:Subject/a:SubjectConfirmation/a:ConfirmationMethod", { "p" => PROTOCOL, "a" => ASSERTION }).text
      raise SA1007Exception unless confirmation_method == settings.idp_confirmation_method
      rescue RuntimeError => exp
        Rails.logger.error "#{exp.class} - #{exp.message}"
        return false
      else
        return true
      end
    end

    # Returns User Principle
    def get_user_principal
      return REXML::XPath.first(document, "/p:Response/a:Assertion/a:AuthenticationStatement/a:Subject/a:NameIdentifier", { "p" => PROTOCOL, "a" => ASSERTION }).text
    end
    
  end
end