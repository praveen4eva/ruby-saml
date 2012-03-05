module Onelogin::Saml
  
	class SA1001Exception < RuntimeError
    def message
			return to_str
		end
		def to_str
			return "Authentication Certificate not found."
		end
  end

	class SA1002Exception < RuntimeError
    def message
			return to_str
		end
		def to_str
			return "Authentication Certificate has expired."
		end
  end

  class SA1003Exception < RuntimeError
		def message
			return to_str
		end
		def to_str
			return "Unable to authenticate. NotBefore condition failed."
		end
	end

  class SA1004Exception < RuntimeError
    def message
      return to_str
    end
    def to_str
      return "Unable to authenticate. NotOnOrAfter condition failed."
    end
  end

  class SA1005Exception < RuntimeError
    def message
      return to_str
    end
    def to_str
      return "Unable to authenticate. ACS URL does not match (Recipient URI check failed)."
    end
  end

  class SA1006Exception < RuntimeError
    def message
      return to_str
    end
    def to_str
      return "Unable to authenticate. No User Principal present in SAML token."
    end
  end

  class SA1007Exception < RuntimeError
    def message
      return to_str
    end
    def to_str
      return "Unable to authenticate. Confirmation Method for browser post profile does not match."
    end
  end

  class SA1008Exception < RuntimeError
    def message
      return to_str
    end
    def to_str
      return "Unable to authenticate. Issuer URI does not match."
    end
  end
  
  class SA1009Exception < RuntimeError
    def message
      return to_str
    end
    def to_str
      return "Unable to authenticate. No User Groups matched."
    end
  end
  
  class SA1010Exception < RuntimeError
    def message
      return to_str
    end
    def to_str
      return "Unable to authenticate. Error getting custom attributes, key not found."
    end
  end

  class SA1011Exception < RuntimeError
    def message
      return to_str
    end
    def to_str
      return "Unable to authenticate. Either the SAML Profile or Signature is not valid."
    end
  end

  class SA1012Exception < RuntimeError
    def message
      return to_str
    end
    def to_str
      return "Unable to decode SAML token. Incorrect SAML token format."
    end
  end

  class SA1013Exception < RuntimeError
    def message
      return to_str
    end
    def to_str
      return "Unable to use token. The SAML response is null."
    end
  end

  class SA1016Exception < RuntimeError
    def message
      return to_str
    end
    def to_str
      return "Direct hit to the application (Referer check fails)."
    end
  end

  class SA1018Exception < RuntimeError
    def message
      return to_str
    end
    def to_str
      return "Unable to authenticate. APID mismatch."
    end
  end

end
