package com.metadium.vc;

import java.net.URI;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.metadium.vc.util.DateUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;


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
	
	private static final String JSONLD_KEY_CREDENTIAL_SUBJECT_ID = "id";
	private static final String JWT_PAYLOAD_VERIFIABLE_CREDENTIAL = "vc";

	
	public VerifiableCredential() {
		super();
	}

	public VerifiableCredential(Map<String, Object> jsonObject) {
		super(jsonObject);
	}
	
	/**
	 * JWT to VerifiableCredential
	 * @param jwt
	 * @return
	 * @throws ParseException
	 */
	@SuppressWarnings("unchecked")
	public VerifiableCredential(SignedJWT jwt) throws ParseException {
		super();
		
		JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
		Map<String, Object> vcClaim = (Map<String, Object>)claimsSet.getClaim(JWT_PAYLOAD_VERIFIABLE_CREDENTIAL);
		if (vcClaim == null) {
			throw new ParseException("Not found vc object", 0);
		}
		
		String id = claimsSet.getJWTID();
		Date expireDate = claimsSet.getExpirationTime();
		String issuer = claimsSet.getIssuer();
		Date issuedDate = claimsSet.getNotBeforeTime();
		String subject = claimsSet.getSubject();
		jsonObject.putAll(vcClaim);
		
		if (id != null) {
			setId(URI.create(id));
		}
		if (expireDate != null) {
			setExpirationDate(expireDate);
		}
		if (issuer != null) {
			Object issuerObject = vcClaim.get(VerifiableCredential.JSONLD_KEY_ISSUSER);
			if (issuerObject instanceof Map) {
				setIssuer(URI.create(issuer), (Map<String, Object>)issuerObject);
			}
			else {
				setIssuer(URI.create(issuer));
			}
		}
		if (issuedDate != null) {
			setIssuanceDate(issuedDate);
		}
		if (subject != null) {
			Object credentialSubject = getCredentialSubject();
			if (credentialSubject instanceof Map) {
				((Map<String, Object>)credentialSubject).put(JSONLD_KEY_CREDENTIAL_SUBJECT_ID, subject);
			}
		}
	}

	@Override
	public String getType() {
		return JSONLD_TYPE_CREDENTIAL;
	}
	
	@SuppressWarnings("unchecked")
	@Override
	JWTClaimsSet toJWT(String nonce, JWTClaimsSet claimsSet) {
		LinkedHashMap<String, Object> vcObject = deepCopy(getJsonObject());

		// From verifiable credential, extract parameters in JWT header
		URI jti = getId();
		Date expireDate = getExpriationDate();
		URI issuer = getIssuer();
		Date issuedDate = getIssunaceDate();
		Object credentialSubject = getCredentialSubject();
		URI subject = null;
		if (credentialSubject instanceof Map) {
			String id = (String)((Map<String, Object>)credentialSubject).get(JSONLD_KEY_CREDENTIAL_SUBJECT_ID);
			if (id != null) {
				subject = URI.create(id);
				// remove id of credential subject
				((Map<String, Object>)vcObject.get(VerifiableCredential.JSONLD_KEY_CREDENTIAL_SUBJECT)).remove(JSONLD_KEY_CREDENTIAL_SUBJECT_ID);
			}
		}
		
		JWTClaimsSet.Builder builder = claimsSet == null ? new JWTClaimsSet.Builder() : new JWTClaimsSet.Builder(claimsSet);
		if (jti != null) {
			// move id to jwt.jti
			builder.jwtID(jti.toString());
			vcObject.remove(Verifiable.JSONLD_KEY_ID);
		}
		if (expireDate != null) {
			// move expire date to jwt.exp
			builder.expirationTime(expireDate);
			vcObject.remove(VerifiableCredential.JSONLD_KEY_EXPIRATION_DATE);
		}
		if (issuer != null) {
			// move issuer to jwt.iss
			builder.issuer(issuer.toString());
			
			vcObject.remove(VerifiableCredential.JSONLD_KEY_ISSUSER);
			Map<String, Object> issuerObject = getIssuerObject();
			if (issuerObject != null) {
				vcObject.put(VerifiableCredential.JSONLD_KEY_ISSUSER, issuerObject);
			}
		}
		if (issuedDate != null) {
			// move issue time to jwt.nbf
			builder.notBeforeTime(issuedDate);
			vcObject.remove(VerifiableCredential.JSONLD_KEY_ISSUANCE_DATE);
		}
		if (subject != null) {
			// set subject credentialSubject.id
			builder.subject(subject.toString());
		}
		if (nonce != null) {
			builder.claim(JWT_HEADER_NONCE, nonce);
		}
		
		builder.claim(JWT_PAYLOAD_VERIFIABLE_CREDENTIAL, vcObject);
		
		return builder.build();
	}


	/**
	 * Set issuer
	 * @param issuer issuer
	 */
	public void setIssuer(URI issuer) {
		jsonObject.put(JSONLD_KEY_ISSUSER, issuer.toString());
	}
	
	
	public void setIssuer(URI issuer, Map<String, ?> issuerObject) {
		Map<String, Object> object = new HashMap<String, Object>(issuerObject);
		object.put("id", issuer.toString());
		jsonObject.put(JSONLD_KEY_ISSUSER, object);
	}
	
	/**
	 * Get issuer
	 * @return issuer of credential
	 */
	public URI getIssuer() {
		Object o = jsonObject.get(JSONLD_KEY_ISSUSER);
		if (o instanceof String) {
			return URI.create((String)o);
		}
		else if (o instanceof Map) {
			@SuppressWarnings("unchecked")
			Object iss = ((Map<String, Object>)o).get("id");
			if (iss != null) {
				return URI.create(iss.toString());
			}
		}
		return null;
	}
	
	/**
	 * Get issuer object
	 * @return object exclude id
	 */
	public Map<String, Object> getIssuerObject() {
		Object o = jsonObject.get(JSONLD_KEY_ISSUSER);
		if (o instanceof Map) {
			@SuppressWarnings("unchecked")
			Map<String, Object> issuerObject = new HashMap<>((Map<String, Object>)o);
			
			issuerObject.remove("id");
			return issuerObject;
		}
		
		return null;
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
	@SuppressWarnings("unchecked")
	public <T> T getCredentialSubject() {
		return (T)jsonObject.get(JSONLD_KEY_CREDENTIAL_SUBJECT);
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
