package org.jaaslounge.decoding;

import java.util.HashMap;
import java.util.Map;

public class DecodingMessages {

	private static Map<String, String> errors = new HashMap<String, String>();
	static {
		errors.put("object_cast_fail", "Unable to cast object from {0} to {1}");
		errors.put("spnego_token_empty", "Empty SPNego token");
		errors.put("spnego_token_invalid", "Not a valid SPNego token: {0}");
		errors.put("spnego_token_malformed", "Malformed SPNego token");
		errors.put("spnego_field_invalid", "Not a valid SPNego token field: {0}");

		errors.put("kerberos_object_cast", "Unable to cast Kerberos object from {0} to {1}");
		errors.put("kerberos_token_empty", "Empty Kerberos token");
		errors.put("kerberos_token_invalid", "Not a Kerberos token");
		errors.put("kerberos_token_malformed", "Malformed Kerberos token");
		errors.put("kerberos_request_empty", "Empty message");
		errors.put("kerberos_request_invalid", "Not a KRB_AP_REQ message");
		errors.put("kerberos_ticket_empty", "Empty Kerberos ticket");
		errors.put("kerberos_ticket_invalid", "Not a Kerberos v5 ticket");
		errors.put("kerberos_ticket_malformed", "Malformed Kerberos ticket");
		errors.put("kerberos_field_invalid", "Not a valid Kerberos ticket field: {0}");
		errors.put("kerberos_field_malformed", "Malformed Kerberos ticket field");
		errors.put("kerberos_key_notfound", "Unable to find appropriate key of type {}");
		errors.put("kerberos_version_invalid", "Invalid version of Kerberos ticket: {0}");
		errors.put("kerberos_login_fail", "Unable to get server keys");
		errors.put("kerberos_decrypt_fail", "Unable to decrypt encrypted data using key of type {0}");

		errors.put("pac_token_empty", "Empty PAC token");
		errors.put("pac_token_malformed", "Malformed PAC token");
		errors.put("pac_logoninfo_malformed", "Malformed PAC logon info");
		errors.put("pac_signature_malformed", "Malformed PAC signature");
		errors.put("pac_signature_invalid", "Invalid PAC signature");
		errors.put("pac_string_notempty", "String not empty while expected null");
		errors.put("pac_string_malformed_size", "Inconsistent string lengths");
		errors.put("pac_string_invalid_size", "Inconsistent string size: {1}, expecting {0}");
		errors.put("pac_groups_invalid_size", "Group count ({0}) doesn't match the real number of groups ({1}) in the PAC");
		errors.put("pac_extrasids_invalid_size", "Extra SID count ({0}) doesn't match the real number of extra SID ({1}) in the PAC");
		errors.put("pac_resourcegroups_invalid_size", "Resource group count ({0}) doesn't match the real number of resource groups ({1}) in the PAC");
		errors.put("pac_sid_malformed_size", "Inconsistent SID length");
		errors.put("pac_subauthority_malformed_size", "Incorrect byte array length: {0}, must be multiple of 4");
		errors.put("pac_version_invalid", "Invalid version of PAC token: {0}");
		errors.put("pac_check_fail", "Unable to check PAC signature");
	};

	private DecodingMessages() {
	}
	
	public static String getString(String key) {
		String msg = "Unknown error";
		
		System.err.println("Deconding key {" + key + "}");
		if (key != null) {
			key = key.replace('.', '_');
			System.err.println("Deconding key {" + key + "}");
			if (errors.containsKey(key)) {
				msg = errors.get(key);
			}
		}
		
		return msg;
	}
}
