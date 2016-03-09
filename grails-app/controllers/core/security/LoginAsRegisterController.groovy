package core.security

import com.larpsecurity.Person
import grails.converters.JSON
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.transaction.Transactional
import org.springframework.security.core.userdetails.UserCache
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.keygen.KeyGenerators

import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

class LoginAsRegisterController {

    def springSecurityService
    //using candidate Map only server decides on the salt
    def static candidateSalt = [:] as ConcurrentHashMap

    def AtomicLong ticketHolder = new AtomicLong((long)(Math.random()*Integer.MAX_VALUE))

    //produces 20 random bytes stream
    def randomSalt(){
        def arr = KeyGenerators.secureRandom(16).generateKey()
        def key = arr.encodeAsBase64()

        key
    }

    def hash(String password,String salt){
        if (!password || !salt){
            println "cannot hash when salt or password are empty"
            return
        }
        MessageDigest sha1 = MessageDigest?.getInstance("SHA1")
        byte[] digest  = sha1.digest("$password$salt"?.getBytes())
        println(new  BigInteger(1, digest)?.toString(16))
    }

    def ticket(){
        ticketHolder?.addAndGet((long)(Math.random()*Integer.MAX_VALUE))
    }

    def preRegister(){
        def ticket = ticket()
        def salt = randomSalt()

        candidateSalt[ticket] = salt

        //respond (['ticket': ticket , 'salt': salt] as Map) as JSON

        render (['ticket': ticket , 'salt': salt] as Map) as JSON
    }

    //call pre-register the get appropriate ticket with hash
    @Transactional
    def register(){
        def uname = params?.username
        if (Person.findByUsername(uname)){
            println "user already exists, cannot re-register"
            render status:404
        }
        def ticket = params.ticket
        def client_hashed_password = params?.password
        def ticketVal = (candidateSalt[Long?.parseLong(ticket)])

        if (!uname || !ticket || !client_hashed_password || !ticketVal){
            println "invalid params, please apply valid credentials for registration with proper ticket after preRegister"
            render status:404
            return;
        }

        def dbSalt = randomSalt()
        def server_hashed_password = hash(client_hashed_password,dbSalt)

        //persist the new user to the database
        Person user = new Person( uname , client_hashed_password)
        user?.setClientSalt( ticketVal )
        //the hashed password-H , will be hashed again using another salt , in the ordinary flow, this prevents situation where as client is compromised for any reason and sends the password as is
        def Person dbUser = user?.save(flush:true , failOnError: true)

        render "persisted ${dbUser?.username}"
    }

    //todo-complete pre login view
    def preLogin(){
        def user = Person?.findByUsername params.username
        if ( user ){
            def ticket = ticket()
            def currentSalt = user?.clientSalt
            def newSalt = randomSalt()
            candidateSalt[ticket] = newSalt

            def res = ['ticket': ticket , 'salt': currentSalt , 'newSalt': newSalt ] as Map
            render view:'preLogin' , model: res
        }

        render view:'preLogin', status: 404
    }

    def login() {
        def encoder = springSecurityService?.passwordEncoder
        def uname = params?.username
        def user = Person?.findByUsername(uname)

        def dbHashedPassword = user?.password
        def originalPassword = params?.oldPassword

        def newPassword = params?.newPassword

        def newSalt = candidateSalt[(Long?.parseLong(params?.ticket))]

        def isValid = encoder?.isPasswordValid(dbHashedPassword, originalPassword, null)
        if (isValid && newPassword && newSalt){
            user?.setPassword( newPassword )
            user?.clientSalt = newSalt
            user?.save(flush: true)

            redirect controller: 'login', action: 'auth'
            //render status: 200 , text: "success"
        }

        render status: 500 , text: "failed to login"
    }
}
