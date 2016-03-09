import com.larpsecurity.Authority
import com.larpsecurity.Person
import com.larpsecurity.PersonAuthority
import com.larpsecurity.Requestmap

class BootStrap {

    def init = { servletContext ->
        initSecurity()
    }
    def destroy = {
    }

    def initSecurity = {
        println "*** Initializing LARP security ***"
        def admin =  Person?.findByUsername('admin') ?: Person.findOrCreateWhere([username: "admin", password: "admin"]).save(failOnError: true)
        def role = Authority?.findByAuthority('SUPERUSER') ?: Authority.findOrCreateWhere([authority:  "SUPERUSER"]).save(failOnError: true)
        def adminRole = PersonAuthority?.findByPersonAndAuthority(admin,role) ?: PersonAuthority.findOrCreateWhere([person: admin, authority: role]).save(failOnError: true)
        //acl
        def acl1 = Requestmap?.findByUrl('/login/**') ?: Requestmap?.findOrCreateWhere([url: '/login/**', configAttribute: 'IS_AUTHENTICATED_ANONYMOUSLY']).save(failOnError: true)
        def acl2 = Requestmap?.findByUrl('/register/**') ?: Requestmap?.findOrCreateWhere([url: '/register/**', configAttribute: 'IS_AUTHENTICATED_ANONYMOUSLY']).save(failOnError: true)
        def acl3 = Requestmap?.findByUrl('/**') ?: Requestmap?.findOrCreateWhere([url: '/**', configAttribute: 'IS_AUTHENTICATED_REMEMBERED']).save(failOnError: true)
    }
}
