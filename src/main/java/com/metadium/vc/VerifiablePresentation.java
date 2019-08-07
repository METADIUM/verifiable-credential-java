package com.metadium.vc;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

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

	public VerifiablePresentation() {
		super();
	}

	public VerifiablePresentation(Map<String, Object> jsonObject) {
		super(jsonObject);
	}

	@Override
	public String getType() {
		return JSONLD_TYPE_PRESENTATION;
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
