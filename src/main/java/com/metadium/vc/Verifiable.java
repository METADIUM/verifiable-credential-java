package com.metadium.vc;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
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
	
	protected static final String JWT_HEADER_NONCE = "nonce";
	
	
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
	 * Verifiable to JWT Claim
	 * @param nonce nonce
	 * @param claimsSet base claimsSet. Nullable 
	 * @return
	 */
	abstract JWTClaimsSet toJWT(String nonce, JWTClaimsSet claimsSet);

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
	 * @param baseClaimsSet JWT 에 포함할 claims. nullable
	 * @return signed verifiable
	 * @throws JOSEException 
	 */
	public SignedJWT sign(JWSAlgorithm algorithm, String kid, String nonce, JWSSigner signer, JWTClaimsSet baseClaimsSet) throws JOSEException  {
		JWTClaimsSet claimsSet = this.toJWT(nonce, baseClaimsSet);
		
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
		return sign(JWSAlgorithm.ES256K, kid, nonce, signer, null);
	}
	
	/**
	 * @see #sign(JWSAlgorithm, String, String, JWSSigner, JWTClaimsSet)
	 *  
	 * @return
	 * @throws JOSEException
	 */
	public SignedJWT sign(String kid, String nonce, ECDSASigner signer, JWTClaimsSet baseClaimsSet) throws JOSEException  {
		return sign(JWSAlgorithm.ES256K, kid, nonce, signer, baseClaimsSet);
	}
	
	/**
	 * Map deep copy
	 * @param src
	 * @return
	 */
	protected static LinkedHashMap<String, Object> deepCopy(LinkedHashMap<String, Object> src) {
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
