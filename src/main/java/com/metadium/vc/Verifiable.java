package com.metadium.vc;

import java.io.IOException;
import java.net.URI;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Verifiable
 * @author mansud
 *
 */
public abstract class Verifiable {
	public static final String JSONLD_CONTEXT = "@context";
	public static final String JSONLD_KEY_ID = "id";
	public static final String JSONLD_KEY_TYPE = "type";
	public static final String JSONLD_KEY_PROOF = "proof";

	// context
	public static final String JSONLD_CONTEXT_CREDENTIALS = "https://w3id.org/credentials/v1";
	
	private static final String JSONLD_KEY_CREDENTIAL_SUBJECT_ID = "id";
	private static final String JWT_HEADER_NONCE = "nonce";
	private static final String JWT_PAYLOAD_VERIFIABLE_CREDENTIAL = "vc";
	private static final String JWT_PAYLOAD_VERIFIABLE_PRESENTATION = "vp";
	
	
	// json object
	protected final LinkedHashMap<String, Object> jsonObject = new LinkedHashMap<>();
	
	
	protected final ObjectMapper objectMapper = new ObjectMapper();
	
	/**
	 * Create with base context
	 */
	public Verifiable() {
		// context
		ArrayList<String> context = new ArrayList<>();
		context.add(JSONLD_CONTEXT_CREDENTIALS);
		jsonObject.put(JSONLD_CONTEXT, context);
		
		ArrayList<String> type = new ArrayList<>();
		type.add(getType());
		
		// type
		jsonObject.put(JSONLD_KEY_TYPE, type);
	}
	
	/**
	 * Create with json object
	 * @param jsonObject
	 */
	public Verifiable(Map<String, Object> jsonObject) {
		this.jsonObject.putAll(jsonObject);
	}
	
	public abstract String getType();

	/**
	 * Add contexts
	 * @param contexts list of context
	 */
	@SuppressWarnings("unchecked")
	public void addContexts(Collection<String> contexts) {
		((List<String>)jsonObject.get(JSONLD_CONTEXT)).addAll(contexts);
	}
	
	/**
	 * Get contexts
	 * @return list of context
	 */
	@SuppressWarnings("unchecked")
	public Collection<String> getContexts() {
		return Collections.unmodifiableCollection(((Collection<String>)jsonObject.get(JSONLD_CONTEXT)));
	}
	
	/**
	 * Set id
	 * @param id of verifiable credential
	 */
	public void setId(URI id) {
		jsonObject.put(JSONLD_KEY_ID, id.toString());
	}
	
	/**
	 * Get id
	 * @return id of verifiable credential
	 */
	public URI getId() {
		String id = (String)jsonObject.get(JSONLD_KEY_ID);
		return id == null ? null : URI.create(id);
	}
	
	/**
	 * Add type list of credential<br>
	 * 
	 * @param types to add
	 */
	@SuppressWarnings("unchecked")
	public void addTypes(Collection<String> types) {
		((List<String>)jsonObject.get(JSONLD_KEY_TYPE)).addAll(types);
	}
	
	/**
	 * Get type list
	 * @return type list
	 */
	@SuppressWarnings("unchecked")
	public Collection<String> getTypes() {
		return Collections.unmodifiableCollection((Collection<String>)jsonObject.get(JSONLD_KEY_TYPE));
	}
	
	
	/**
	 * Get json string from verifiable credential
	 * @return json string
	 */
	public String toJSONString() {
		try {
			return objectMapper.writeValueAsString(jsonObject);
		} catch (JsonProcessingException e) {
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

	/**
	 * Set proof
	 * @param proof
	 */
	public void setProof(Object proof) {
		jsonObject.put(JSONLD_KEY_PROOF, proof);
	}
	
	/**
	 * Get proof
	 * @return proof object
	 */
	public Object getProof() {
		return jsonObject.get(JSONLD_KEY_PROOF);
	}
	
	/**
	 * Sign verifiable
	 * @param algorithm JWS algorithm. recommend {@link JWSAlgorithm#ES256K}
	 * @param kid key id (DID) of signer. "did:meta:0x384394#key1"
	 * @param nonce to avoid replay attack
	 * @param signer signer object. recommend {@link ECDSASigner}
	 * @return signed verifiable
	 * @throws JOSEException 
	 */
	public SignedJWT sign(JWSAlgorithm algorithm, String kid, String nonce, JWSSigner signer) throws JOSEException  {
		JWTClaimsSet claimsSet;
		if (this instanceof VerifiableCredential) {
			claimsSet = credentialToJWT((VerifiableCredential)this, nonce);
		}
		else if (this instanceof VerifiablePresentation) {
			claimsSet = presentationToJWT((VerifiablePresentation)this, nonce);
		}
		else {
			return null;
		}
		
		// sign to JWT
		signer.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		JWSHeader jwsHeader = new JWSHeader(algorithm, JOSEObjectType.JWT, null, null, null, null, null, null, null, null, kid, null, null);
		SignedJWT jwts = new SignedJWT(jwsHeader, claimsSet);
		jwts.sign(signer);
		
		return jwts;
	}
	
	/**
	 * Sign verifiable
	 * @param algorithm JWS algorithm. recommend {@link JWSAlgorithm#ES256K}
	 * @param kid key id (DID) of signer. "did:meta:0x384394#key1"
	 * @param nonce to avoid replay attack
	 * @param signer signer object. recommend {@link ECDSASigner}
	 * @return signed verifiable
	 * @throws JOSEException 
	 */
	public SignedJWT sign(String kid, String nonce, ECDSASigner signer) throws JOSEException  {
		return sign(JWSAlgorithm.ES256K, kid, nonce, signer);
	}
	
	/**
	 * signed verifiable to Verifiable
	 * @param signedVerifiable signed verifiable
	 * @return verifiable object
	 * @throws ParseException invalid signed verifiable
	 * @throws JOSEException
	 */
	public static Verifiable from(SignedJWT signedVerifiable) throws ParseException, JOSEException {
		JWTClaimsSet claims = signedVerifiable.getJWTClaimsSet();
		if (claims.getClaim(JWT_PAYLOAD_VERIFIABLE_CREDENTIAL) != null) {
			return toCredential(claims);
		}
		else if (claims.getClaim(JWT_PAYLOAD_VERIFIABLE_PRESENTATION) != null) {
			return toPresentation(claims);
		}
		return null;
	}
	
	/**
	 * signed verifiable to Verifiable
	 * @param signedVerifiable signed verifiable json
	 * @return verifiable object
	 * @throws ParseException invalid signed verifiable
	 * @throws JOSEException
	 */
	public static Verifiable from(String signedVerifiableJson) throws ParseException, JOSEException {
		return Verifiable.from(SignedJWT.parse(signedVerifiableJson));
	}
	
	/**
	 * convert from JWT to Verifiable credential.
	 * @see <a href="https://w3c.github.io/vc-data-model/#jwt-decoding">JWT Decoding</a>
	 * @param claimsSet JWT
	 * @return verifiable credential
	 */
	@SuppressWarnings("unchecked")
	private static VerifiableCredential toCredential(JWTClaimsSet claimsSet) {
		String id = claimsSet.getJWTID();
		Date expireDate = claimsSet.getExpirationTime();
		String issuer = claimsSet.getIssuer();
		Date issuedDate = claimsSet.getIssueTime();
		String subject = claimsSet.getSubject();
		Map<String, Object> vcClaim = (Map<String, Object>)claimsSet.getClaim(JWT_PAYLOAD_VERIFIABLE_CREDENTIAL);
		
		VerifiableCredential vc = new VerifiableCredential(vcClaim);
		if (id != null) {
			vc.setId(URI.create(id));
		}
		if (expireDate != null) {
			vc.setExpirationDate(expireDate);
		}
		if (issuer != null) {
			Object issuerObject = vcClaim.get(VerifiableCredential.JSONLD_KEY_ISSUSER);
			if (issuerObject instanceof Map) {
				vc.setIssuer(URI.create(issuer), (Map<String, Object>)issuerObject);
			}
			else {
				vc.setIssuer(URI.create(issuer));
			}
		}
		if (issuedDate != null) {
			vc.setIssuanceDate(issuedDate);
		}
		if (subject != null) {
			Object credentialSubject = vc.getCredentialSubject();
			if (credentialSubject instanceof Map) {
				((Map<String, Object>)credentialSubject).put(JSONLD_KEY_CREDENTIAL_SUBJECT_ID, subject);
			}
		}
		
		return vc;
	}
	
	/**
	 * convert from JWT to Verifiable presentation.
	 * @see <a href="https://w3c.github.io/vc-data-model/#jwt-decoding">JWT Decoding</a>
	 * @param claimsSet JWT
	 * @return verifiable presentation
	 */
	@SuppressWarnings("unchecked")
	private static VerifiablePresentation toPresentation(JWTClaimsSet claimsSet) {
		String id = claimsSet.getJWTID();
		String holder = claimsSet.getIssuer();
		
		Object vpClaim = claimsSet.getClaim(JWT_PAYLOAD_VERIFIABLE_PRESENTATION);
		
		VerifiablePresentation vp = new VerifiablePresentation((Map<String, Object>)vpClaim);
		if (id != null) {
			vp.setId(URI.create(id));
		}
		if (holder != null) {
			vp.setHolder(URI.create(holder));
		}
		
		return vp;
	}
	
	/**
	 * Convert from verifiable credential to JWT
	 * @param vc	verifiable credential
	 * @param nonce to avoid replay attack
	 * @return JWT
	 */
	@SuppressWarnings("unchecked")
	private static JWTClaimsSet credentialToJWT(VerifiableCredential vc, String nonce) {
		LinkedHashMap<String, Object> vcObject = deepCopy(vc.getJsonObject());

		// From verifiable credential, extract parameters in JWT header
		URI jti = vc.getId();
		Date expireDate = vc.getExpriationDate();
		URI issuer = vc.getIssuer();
		Date issuedDate = vc.getIssunaceDate();
		Object credentialSubject = vc.getCredentialSubject();
		URI subject = null;
		if (credentialSubject instanceof Map) {
			String id = (String)((Map<String, Object>)credentialSubject).get(JSONLD_KEY_CREDENTIAL_SUBJECT_ID);
			if (id != null) {
				subject = URI.create(id);
				// remove id of credential subject
				((Map<String, Object>)vcObject.get(VerifiableCredential.JSONLD_KEY_CREDENTIAL_SUBJECT)).remove(JSONLD_KEY_CREDENTIAL_SUBJECT_ID);
			}
		}
		
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
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
			Map<String, Object> issuerObject = vc.getIssuerObject();
			if (issuerObject != null) {
				vcObject.put(VerifiableCredential.JSONLD_KEY_ISSUSER, issuerObject);
			}
		}
		if (issuedDate != null) {
			// move issue time to jwt.nbf
			builder.issueTime(issuedDate);
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
	 * Convert from verifiable presentation to JWT
	 * @param vc	verifiable presentation
	 * @param nonce to avoid replay attack
	 * @return JWT
	 * @throws IOException 
	 */
	private static JWTClaimsSet presentationToJWT(VerifiablePresentation vp, String nonce) {
		LinkedHashMap<String, Object> vpObject = deepCopy(vp.getJsonObject());
		 
		// From verifiable credential, extract parameters in JWT header
		URI jti = vp.getId();
		URI holder = vp.getHolder();
		
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
		if (jti != null) {
			// move id to jwt.jti
			builder.jwtID(jti.toString());
			vpObject.remove(Verifiable.JSONLD_KEY_ID);
		}
		if (holder != null) {
			builder.issuer(holder.toString());
			vpObject.remove(VerifiablePresentation.JSONLD_KEY_HOLDER);
		}
		if (nonce != null) {
			builder.claim(JWT_HEADER_NONCE, nonce);
		}
		
		builder.claim(JWT_PAYLOAD_VERIFIABLE_PRESENTATION, vpObject);
		
		return builder.build();
	}

	/**
	 * Map deep copy
	 * @param src
	 * @return
	 */
	private static LinkedHashMap<String, Object> deepCopy(LinkedHashMap<String, Object> src) {
		ObjectMapper objectMapper = new ObjectMapper();
		
		try {
			byte[] data = objectMapper.writeValueAsBytes(src);
			return objectMapper.readValue(data, new TypeReference<LinkedHashMap<String, Object>>() {});
		} catch (IOException e) {
		}
		// not happened
		return null;
	}
}
