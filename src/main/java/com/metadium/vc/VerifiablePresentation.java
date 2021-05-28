package com.metadium.vc;

import java.io.IOException;
import java.net.URI;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * VerifiablePresentation
 * Based on @see <a href="https://w3c.github.io/vc-data-model/#presentations-0">Presentation</a>
 * @author mansud
 *
 */
public class VerifiablePresentation extends Verifiable {
	public static final String JSONLD_KEY_VERIFIABLE_CREDENTIAL = "verifiableCredential";
	public static final String JSONLD_KEY_HOLDER = "holder";

	// type
	public static final String JSONLD_TYPE_PRESENTATION = "VerifiablePresentation";
	
	private static final String JWT_PAYLOAD_VERIFIABLE_PRESENTATION = "vp";

	public VerifiablePresentation() {
		super();
	}

	public VerifiablePresentation(Map<String, Object> jsonObject) {
		super(jsonObject);
	}
	
	@SuppressWarnings("unchecked")
	public VerifiablePresentation(SignedJWT jwt) throws ParseException {
		super();
		
		JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
		Object vpClaim = claimsSet.getClaim(JWT_PAYLOAD_VERIFIABLE_PRESENTATION);
		if (vpClaim == null) {
			throw new ParseException("Not found vp object", 0);
		}

		String id = claimsSet.getJWTID();
		String holder = claimsSet.getIssuer();
		
		jsonObject.putAll((Map<String, Object>)vpClaim);
		if (id != null) {
			setId(URI.create(id));
		}
		if (holder != null) {
			setHolder(URI.create(holder));
		}
	}

	@Override
	public String getType() {
		return JSONLD_TYPE_PRESENTATION;
	}
	
	/**
	 * Convert from verifiable presentation to JWT
	 * @param vc	verifiable presentation
	 * @param nonce to avoid replay attack
	 * @return JWT
	 * @throws IOException 
	 */
	@Override
	JWTClaimsSet toJWT(String nonce, JWTClaimsSet claimsSet) {
		LinkedHashMap<String, Object> vpObject = deepCopy(getJsonObject());
		 
		// From verifiable credential, extract parameters in JWT header
		URI jti = getId();
		URI holder = getHolder();
		
		JWTClaimsSet.Builder builder = claimsSet == null ? new JWTClaimsSet.Builder() : new JWTClaimsSet.Builder(claimsSet);
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
	 * Add verifiable credential
	 * @param vc verifiable credential
	 */
	@SuppressWarnings("unchecked")
	public void addVerifiableCredential(Object vc) {
		ArrayList<Object> vcList = (ArrayList<Object>)jsonObject.get(JSONLD_KEY_VERIFIABLE_CREDENTIAL);
		if (vcList == null) {
			vcList = new ArrayList<>();
			jsonObject.put(JSONLD_KEY_VERIFIABLE_CREDENTIAL, vcList);
		}
		vcList.add(vc);
	}
	
	/**
	 * Get list of verifiable credential
	 * @return list of verifiable credential
	 */
	@SuppressWarnings("unchecked")
	public Collection<Object> getVerifiableCredentials() {
		Object list = jsonObject.get(JSONLD_KEY_VERIFIABLE_CREDENTIAL);
		if (list != null) {
			return Collections.unmodifiableCollection((Collection<Object>)list);
		}
		return null;
	}
	
	/**
	 * Set holder
	 * @param holder of presentation
	 */
	public void setHolder(URI holder) {
		jsonObject.put(JSONLD_KEY_HOLDER, holder.toString());
	}
	
	/**
	 * Get holder
	 * @return holder of presentation
	 */
	public URI getHolder() {
		return URI.create((String)jsonObject.get(JSONLD_KEY_HOLDER));
	}

}
