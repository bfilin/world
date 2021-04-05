(* This parameter controls how frequently we find an out-of-date GitHub profile
 * and ask github.com for the latest data.  It's in seconds. *)
val updateFrequency = 30

open Json

table users : { Login : string,
                AvatarUrl : string,
                Nam : option string,
                Company : option string,
                Blog : option string,
                Location : option string,
                Email : option string,
                Hireable : option bool,
                Bio : option string,
                LastUpdated : time }
  PRIMARY KEY Login

con users_hidden_constraints = _
constraint [Pkey = [Login]] ~ users_hidden_constraints

table secrets : { Login : string,
                  Secret : int }
  PRIMARY KEY Login,
  CONSTRAINT Login FOREIGN KEY Login REFERENCES users(Login) ON DELETE CASCADE

cookie user : { Login : string, Secret : int }

signature S = sig
    val client_id : string
    val client_secret : string
    val org_name : string
    val https : bool
    val scope : string
    val onCompletion : transaction page
end


type org_profile = { Orgname: string }
val json_org_profile : json org_profile = json_record { Orgname = "login"}

type profile = { Login : string,
                 AvatarUrl : string,
                 Nam : option string,
                 Company : option string,
                 Blog : option string,
                 Location : option string,
                 Email : option string,
                 Hireable : option bool,
                 Bio : option string }

val json_profile : json profile =
    json_record {Login = "login",
                 AvatarUrl = "avatar_url",
                 Nam = "name",
                 Company = "company",
                 Blog = "blog",
                 Location = "location",
                 Email = "email",
                 Hireable = "hireable",
                 Bio = "bio"}

functor Make(M : S) = struct
    open M

    fun updateProfile url tokOpt =
        profile <- WorldFfi.get url (Option.mp (fn s => "token " ^ s) tokOpt) False;
        (profile : profile) <- return (Json.fromJson profile);
        exists <- oneRowE1 (SELECT COUNT( * ) > 0
                            FROM users
                            WHERE users.Login = {[profile.Login]});
        (if exists then
             dml (UPDATE users
                  SET AvatarUrl = {[profile.AvatarUrl]},
                    Nam = {[profile.Nam]},
                    Company = {[profile.Company]},
                    Blog = {[profile.Blog]},
                    Location = {[profile.Location]},
                    Email = {[profile.Email]},
                    Hireable = {[profile.Hireable]},
                    Bio = {[profile.Bio]},
                    LastUpdated = CURRENT_TIMESTAMP
                  WHERE Login = {[profile.Login]})
         else
             dml (INSERT INTO users(Login, AvatarUrl, Nam, Company, Blog, Location,
                      Email, Hireable, Bio, LastUpdated)
                  VALUES ({[profile.Login]}, {[profile.AvatarUrl]}, {[profile.Nam]},
                      {[profile.Company]}, {[profile.Blog]}, {[profile.Location]},
                      {[profile.Email]}, {[profile.Hireable]}, {[profile.Bio]},
                      CURRENT_TIMESTAMP)));
        return profile.Login


    fun verifyOrg url tokOpt =
        let
                fun checkOrgs o =
                        (*  debug ("@ debug ---------- checkOrgs o: " ^ show o); *)
                        let
                                fun checkOrgs' o =
                                        (org_profile : org_profile) <- return (Json.fromJson o);
					if org_profile.Orgname = org_name then
						return org_profile.Orgname
					else
                                                 error <xml> You are not authorized for access (c-lp2)</xml>
                
                                fun checkOrgs'' f s = 
                                        (org_profile : org_profile) <- return (Json.fromJson  (f ^ "}"));
					if org_profile.Orgname = org_name then
						return org_profile.Orgname
					else
                                                 checkOrgs s

                        in
                                case String.ssplit {Haystack = o , Needle = "},"} of
                                    None => checkOrgs' o 
                                  | Some (f,s) => checkOrgs'' f s 
                        end
        in      

                m <- WorldFfi.get url (Option.mp (fn s => "token " ^ s) tokOpt) False;
                lens <- return (String.length m);
		(* github returns [], remove it *)
                if lens > 2 && String.sub m 0 = #"["
                then
                        checkOrgs (String.substring m {Start = 1, Len = lens-2}) 
                else 
                        error <xml> error You are not authorized for access (c-lp1)"</xml>

        end



    fun withToken {Token = tok, ...} =
        login <- updateProfile (bless "https://api.github.com/user") (Some tok);
        m <- verifyOrg (bless "https://api.github.com/user/orgs") (Some tok);  
        debug ('@ debug - github user:[' ^ login ^ ']-  verifyOrg returned : [' ^ m ^ ']'); 


        secret <- oneOrNoRowsE1 (SELECT (secrets.Secret)
                                 FROM secrets
                                 WHERE secrets.Login = {[login]});
        secret <- (case secret of
                       Some secret => return secret
                     | None =>
                       secret <- rand;
                       dml (INSERT INTO secrets(Login, Secret)
                            VALUES ({[login]}, {[secret]}));
                       return secret);

        setCookie user {Value = {Login = login, Secret = secret},
                        Expires = None,
                        Secure = https}

    open Oauth.Make(struct
                        open M

                        val authorize_url = bless "https://github.com/login/oauth/authorize"
                        val access_token_url = bless "https://github.com/login/oauth/access_token"
                        val withToken = withToken
                        val scope = Some M.scope
                        val nameForScopeParameter = None
                        val parseTokenResponse = None
                    end)

    val whoami =
        c <- getCookie user;
        case c of
            None => return None
          | Some r =>
            ok <- oneRowE1 (SELECT COUNT( * ) > 0
                            FROM secrets
                            WHERE secrets.Login = {[r.Login]}
                              AND secrets.Secret = {[r.Secret]});
            if ok then
                return (Some r.Login)
            else
                return None


    val requireLogin =
        debug("github.ur requireLogin started");
        o <- whoami;          
        case o of             
            None => error <xml>Access denied (must be logged in)</xml>                                                     
          | Some _ => return ()     


    fun trackUser login =
        Monad.ignore (updateProfile (bless ("https://api.github.com/users/" ^ login)) None)

    val oneDay = 60 * 60 * 24

    task periodic updateFrequency = fn () =>
         tm <- now;
         oldTime <- return (addSeconds tm (-oneDay));
         outOfDate <- oneOrNoRowsE1 (SELECT (users.Login)
                                     FROM users
                                     WHERE users.LastUpdated < {[oldTime]}
                                     LIMIT 1);
         case outOfDate of
             None => return ()
           | Some login =>
             Monad.ignore (updateProfile (bless ("https://api.github.com/users/" ^ login)) None)

    val logout = clearCookie user
end
