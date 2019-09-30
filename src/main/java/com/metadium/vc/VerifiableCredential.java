package com.metadium.vc;

import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.metadium.vc.util.DateUtils;


/**
 * VerifiableCredential<br>
 * Based on @see <a href="https://w3c.github.io/vc-data-model/#basic-concepts">Verifiable Credentials Data Model 1.0</a>
 * @author mansud
 *
 */
public class VerifiableCredential extends Verifiable {
	public static final String JSONLD_KEY_CREDENTIAL_SUBJECT = "credentialSubject";
	public static final String JSONLD_KEY_ISSUSER = "issuer";
	public static final String JSONLD_KEY_ISSUANCE_DATE = "issuanceDate";
	public static final String JSONLD_KEY_EXPIRATION_DATE = "expirationDate";
	public static final String JSONLD_KEY_CREDENTIALS_STATUS = "credentialStatus";
	
	// type
	public static final String JSONLD_TYPE_CREDENTIAL = "VerifiableCredential";
	
	public VerifiableCredential() {
		super();
	}

	public VerifiableCredential(Map<String, Object> jsonObject) {
		super(jsonObject);
	}

	@Override
	public String getType() {
		return JSONLD_TYPE_CREDENTIAL;
	}

	/**
	 * Set issuer
	 * @param issuer issuer
	 */
	public void setIssuer(URI issuer) {
		jsonObject.put(JSONLD_KEY_ISSUSER, issuer.toString());
	}
	
	/**
	 * Get issuer
	 * @return issuer of credential
	 */
	public URI getIssuer() {
		return URI.create((String)jsonObject.get(JSONLD_KEY_ISSUSER));
	}
	
	/**
	 * Set issued date of credential
	 * @param date date
	 */
	public void setIssuanceDate(Date date) {
		jsonObject.put(JSONLD_KEY_ISSUANCE_DATE, DateUtils.toRFC3339UTC(date));
	}
	
	/**
	 * Get issued date of credential
	 * @return issued date
	 */
	public Date getIssunaceDate() {
		String date = ((String)jsonObject.get(JSONLD_KEY_ISSUANCE_DATE));
		if (date != null) {
			return DateUtils.fromRFC3339UTC(date);
		}
		
		return null;
	}
	
	/**
	 * Set expire date of credential
	 * @param date date
	 */
	public void setExpirationDate(Date date) {
		jsonObject.put(JSONLD_KEY_EXPIRATION_DATE, DateUtils.toRFC3339UTC(date));
	}
	
	/**
	 * Get expire date of credential
	 * @return expire date
	 */
	public Date getExpriationDate() {
		String date = (String)jsonObject.get(JSONLD_KEY_EXPIRATION_DATE);
		if (date != null) {
			return DateUtils.fromRFC3339UTC(date);
		}
		return null;
	}
	
	/**
	 * Set status of credential
	 * @param id	status id
	 * @param type	credential status type
	 */
	public void setCredentialStatus(URI id, String type) {
		LinkedHashMap<String, Object> status = new LinkedHashMap<>();
		status.put("id", id.toString());
		status.put("type", type);
		jsonObject.put(JSONLD_KEY_CREDENTIALS_STATUS, status);
	}
	
	/**
	 * Get id of credential status
	 * @return id
	 */
	@SuppressWarnings("unchecked")
	public URI getCredentialStatusId() {
		Object status = jsonObject.get(JSONLD_KEY_CREDENTIALS_STATUS);
		if (status instanceof HashMap) {
			Object id = ((Map<String, Object>)status).get("id");
			if (id instanceof String) {
				return URI.create((String)id);
			}
		}
		return null;
	}
	
	/**
	 * Get type of credentail status
	 * @return type
	 */
	@SuppressWarnings("rawtypes")
	public String getCredentialStatusType() {
		Object status = jsonObject.get(JSONLD_KEY_CREDENTIALS_STATUS);
		if (status instanceof HashMap) {
			return (String)((Map)status).get("type");
		}
		return null;
	}
	
	/**
	 * Set credential subject
	 * @param subject credential subject
	 */
	public void setCredentialSubject(Object subject) {
		jsonObject.put(JSONLD_KEY_CREDENTIAL_SUBJECT, subject);
	}
	
	/**
	 * Get credential subject 
	 * @return credential subject
	 */
	public Object getCredentialSubject() {
		return jsonObject.get(JSONLD_KEY_CREDENTIAL_SUBJECT);
	}

	/**
	 * Get json string from verifiable credential
	 * @return json string
	 */
	public String toJSONString() {
		try {
			return objectMapper.writeValueAsString(jsonObject);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Get json object
	 * @return json object
	 */
	public LinkedHashMap<String, Object> getJsonObject() {
		return jsonObject;
	}
}
