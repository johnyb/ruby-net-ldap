# -*- ruby encoding: utf-8 -*-
require 'digest/sha1'
require 'digest/md5'
require 'base64'

class Net::LDAP::Password

  PasswdModifyOID = "1.3.6.1.4.1.4203.1.11.1"

  def initialize(args = {})
    @user_id = args[:dn]
    @old_password = args[:old_password]
    @new_password = args[:new_password]
  end

  class << self
    # Generate a password-hash suitable for inclusion in an LDAP attribute.
    # Pass a hash type as a symbol (:md5, :sha, :ssha) and a plaintext
    # password. This function will return a hashed representation.
    #
    #--
    # STUB: This is here to fulfill the requirements of an RFC, which
    # one?
    #
    # TODO:
    # * maybe salted-md5
    # * Should we provide sha1 as a synonym for sha1? I vote no because then
    #   should you also provide ssha1 for symmetry?
    #
    attribute_value = ""
    def generate(type, str)
       case type
         when :md5
            attribute_value = '{MD5}' + Base64.encode64(Digest::MD5.digest(str)).chomp! 
         when :sha
            attribute_value = '{SHA}' + Base64.encode64(Digest::SHA1.digest(str)).chomp! 
         when :ssha
            srand; salt = (rand * 1000).to_i.to_s 
            attribute_value = '{SSHA}' + Base64.encode64(Digest::SHA1.digest(str + salt) + salt).chomp!
         else
            raise Net::LDAP::LdapError, "Unsupported password-hash type (#{type})"
         end
      return attribute_value
    end

  end

  def to_ber
    request = [ PasswdModifyOID.to_ber_contextspecific(2) ]
    request << payload.to_ber_sequence unless payload.empty?
    request.to_ber_appsequence(Net::LDAP::PDU::ExtendedRequest)
  end

  private
    def payload
      payload = []
      payload << @user_id.to_ber if @user_id
      payload << @old_password.to_ber if @old_password
      payload << @new_password.to_ber if @new_password
      return payload
    end
end
