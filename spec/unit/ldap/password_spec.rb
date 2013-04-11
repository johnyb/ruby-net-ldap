require 'spec_helper'

describe Net::LDAP::Password do
  describe 'RFC 3062 - LDAP Password Modify Extended Operation' do

    let(:oid) { /1\.3\.6\.1\.4\.1\.4203\.1\.11\.1/ }

    describe 'request values' do
      it "should end with the password modify oid, without any payload" do
        pwd = Net::LDAP::Password.new
        test = pwd.to_ber.gsub(/\s/, '#') # replace evil chars
        test.should =~ /#{oid}$/
      end

      it "should end with the old password as only parameter" do
        pwd = Net::LDAP::Password.new(:old_password => "old_secure")
        test = pwd.to_ber.gsub(/\s/, '#') # replace evil chars
        test.should =~ /#{oid}.*old_secure$/
      end

      it "should end with the new password as only parameter" do
        pwd = Net::LDAP::Password.new(:new_password => "new_secure")
        test = pwd.to_ber.gsub(/\s/, '#') # replace evil chars
        test.should =~ /#{oid}.*new_secure$/
      end

      it "should end with the uid as only parameter" do
        pwd = Net::LDAP::Password.new(:dn => "cn=Robert")
        test = pwd.to_ber.gsub(/\s/, '#') # replace evil chars
        test.should =~ /#{oid}.*cn=Robert$/
      end

      it "should contain uid, old password and new password in exactly this order" do
        pwd = Net::LDAP::Password.new(:new_password => "new_secure",
                                      :dn => "cn=Robert",
                                      :old_password => "old_secure")
        uid_index = pwd.to_ber.index("cn=Robert")
        old_index = pwd.to_ber.index("old_secure")
        new_index = pwd.to_ber.index("new_secure")
        uid_index.should_not be_nil
        old_index.should_not be_nil
        new_index.should_not be_nil
        uid_index.should < old_index
        old_index.should < new_index
      end
    end
  end
end
