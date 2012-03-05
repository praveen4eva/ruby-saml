# The contents of this file are subject to the terms
# of the Common Development and Distribution License
# (the License). You may not use this file except in
# compliance with the License.
#
# You can obtain a copy of the License at
# https://opensso.dev.java.net/public/CDDLv1.0.html or
# opensso/legal/CDDLv1.0.txt
# See the License for the specific language governing
# permission and limitations under the License.
#
# When distributing Covered Code, include this CDDL
# Header Notice in each file and include the License file
# at opensso/legal/CDDLv1.0.txt.
# If applicable, add the following below the CDDL Header,
# with the fields enclosed by brackets [] replaced by
# your own identifying information:
# "Portions Copyrighted [year] [name of copyright owner]"
#
# $Id: xml_sec.rb,v 1.6 2007/10/24 00:28:41 todddd Exp $
#
# Copyright 2007 Sun Microsystems Inc. All Rights Reserved
# Portions Copyrighted 2007 Todd W Saxton.

require 'rubygems'
require "rexml/document"
require "rexml/xpath"
require "openssl"
require "xmlcanonicalizer"
require "digest/sha1"
require "onelogin/saml/samlexceptions"

module XMLSecurity

  class SignedDocument < REXML::Document

    include Onelogin::Saml

    ASSERTION = "urn:oasis:names:tc:SAML:1.0:assertion"
    PROTOCOL  = "urn:oasis:names:tc:SAML:1.0:protocol"
    DSIG      = "http://www.w3.org/2000/09/xmldsig#"

    attr_accessor :signed_element_id

    def initialize(response)
      super(response)
      extract_signed_element_id
    end

    def validate (idp_cert_fingerprint, logger = nil)
      begin
        # Get X.509 Certificate from Response
        base64_certificate             = REXML::XPath.first(self, "/p:Response/a:Assertion/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate", { "p" => PROTOCOL, "a" => ASSERTION, "ds" => DSIG }).text
        certificate_text               = Base64.decode64(base64_certificate)
        certificate                    = OpenSSL::X509::Certificate.new(certificate_text)

        # Validate Obtained Certificate with Registered Certificate using Fingerprint
        fingerprint             = Digest::SHA1.hexdigest(certificate.to_der)
        valid_flag              = fingerprint == idp_cert_fingerprint.gsub(":", "").downcase

        raise SA1001Exception if !valid_flag

        return false unless validate_digest(base64_certificate, logger)
      rescue SA1011Exception => exp
        Rails.logger.error "#{exp.class} - #{exp.message}"
        return false
      rescue RuntimeError => exp
        Rails.logger.error "#{exp.class} - #{exp.message}"
        return false
      else
        return true
      end
    end

    def validate_digest(base64_certificate, logger)
      begin
        signed_element = REXML::XPath.first(self,"/p:Response/a:Assertion/ds:Signature", { "p" => PROTOCOL, "a" => ASSERTION, "ds" => DSIG })
        signed_element.remove

        # Check Digest Values
        REXML::XPath.each(signed_element, "ds:SignedInfo/ds:Reference", { "ds" => DSIG }) do | ref |
          uri                   = ref.attributes.get_attribute("URI").value
          hashed_element        = REXML::XPath.first(self, "//a:Assertion[@AssertionID='#{uri[1,uri.size]}']", { "a" => ASSERTION })
          canoner               = XML::Util::XmlCanonicalizer.new(false, true)
          canon_hashed_element  = canoner.canonicalize(hashed_element)
          hash                  = Base64.encode64(Digest::SHA1.digest(canon_hashed_element)).chomp
          digest_value          = REXML::XPath.first(ref, "ds:DigestValue", { "ds" => DSIG }).text
          valid_flag            = hash == digest_value
          raise SA1011Exception if !valid_flag
        end

        # Verify Signature
        canoner                 = XML::Util::XmlCanonicalizer.new(false, true)
        signed_info_element     = REXML::XPath.first(signed_element, "ds:SignedInfo", { "p" => PROTOCOL, "a" => ASSERTION, "ds" => DSIG })
        canon_string            = canoner.canonicalize(signed_info_element)

        base64_signature        = REXML::XPath.first(signed_element, "ds:SignatureValue", { "p" => PROTOCOL, "a" => ASSERTION, "ds" => DSIG }).text
        signature               = Base64.decode64(base64_signature)

        # Get Certificate Object
        certificate_text        = Base64.decode64(base64_certificate)
        certificate             = OpenSSL::X509::Certificate.new(certificate_text)

        # Validate Signature Values
        valid_flag              = certificate.public_key.verify(OpenSSL::Digest::SHA1.new, signature, canon_string)

        raise SA1011Exception if !valid_flag
      rescue SA1011Exception => exp
        Rails.logger.error "#{exp.class} - #{exp.message}"
        return false
      rescue RuntimeError => exp
        Rails.logger.error "#{exp.class} - #{exp.message}"
        return false
      else
        return true
      end
    end

    private

    def extract_signed_element_id
      reference_element       = REXML::XPath.first(self, "/p:Response/a:Assertion/ds:Signature/ds:SignedInfo/ds:Reference", { "p" => PROTOCOL, "a" => ASSERTION, "ds" => DSIG })
      self.signed_element_id  = reference_element.attribute("URI").value unless reference_element.nil?
    end
  end
end
