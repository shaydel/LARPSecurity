package com.larpsecurity

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString

@EqualsAndHashCode(includes='username')
@ToString(includes='username', includeNames=true, includePackage=false)
class Person implements Serializable {

	private static final long serialVersionUID = 1

	transient springSecurityService

	String username
	String password
	String clientSalt
	boolean enabled = true
	boolean accountExpired
	boolean accountLocked
	boolean passwordExpired

	Person(String username, String password) {
		this()
		this.username = username
		this.password = password
	}

	Set<Authority> getAuthorities() {
		PersonAuthority.findAllByPerson(this)*.authority
	}

	def beforeInsert() {
		encodePassword()
	}

	def beforeUpdate() {
		if (isDirty('password')) {
			encodePassword()
		}
	}

	protected void encodePassword() {
		password = springSecurityService?.passwordEncoder ? springSecurityService.encodePassword(password) : password
	}

	static transients = ['springSecurityService']

	static constraints = {
		username blank: false, unique: true
		password blank: false
	}

	static mapping = {
		password column: '`password`'
	}
}
