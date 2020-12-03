[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

![Superset Keycloak](https://github.com/akashanita/superset-keycloak/blob/main/superset-keycloak.jpeg)

# Superset Integration with Keycloak
**Superset** is emerging data visualization tool which help common people to represent data in an understanding and graphical way.

**Keycloak** is an open source software product to allow single sign-on with Identity and Access Management aimed at modern applications and services.

Both are emerging tools and popular among developers and data engineers. Thus we think that these technologies need to be integrate.

## Superset Capabilities
-   An intuitive interface to explore and visualize datasets, and create interactive dashboards.
-   A wide array of beautiful visualizations to showcase your data.
-   Easy, code-free, user flows to drill down and slice and dice the data underlying exposed dashboards. The dashboards and charts act as a starting point for deeper analysis.
-   A state of the art SQL editor/IDE exposing a rich metadata browser, and an easy workflow to create visualizations out of any result set.
-   An extensible, high granularity security model allowing intricate rules on who can access which product features and datasets. Integration with major authentication backends (database, OpenID, LDAP, OAuth, REMOTE_USER, ...)
-   A lightweight semantic layer, allowing to control how data sources are exposed to the user by defining dimensions and metrics
-   Out of the box support for most SQL-speaking databases
-   Deep integration with Druid allows for Superset to stay blazing fast while slicing and dicing large, realtime datasets
-   Fast loading dashboards with configurable caching


## Keycloak Capabilities

-   User Registration
-   [Social login](https://en.wikipedia.org/wiki/Social_login "Social login")
-   [Single Sign-On](https://en.wikipedia.org/wiki/Single_sign-on "Single sign-on")/Sign-Off across all applications belonging to the same Realm
-   [2-factor authentication](https://en.wikipedia.org/wiki/Multi-factor_authentication "Multi-factor authentication")
-   [LDAP](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol "Lightweight Directory Access Protocol")  integration
-   [Kerberos](https://en.wikipedia.org/wiki/Kerberos_(protocol) "Kerberos (protocol)")  broker
-   multitenancy with per-realm customizable skin

## Configurations
To integration superset with existing keycloak, We need to provide keycloak details as environment variables. We can also provide these environment variables in **.env** file which is placed in docker folder in this repository.
 
    ADMIN_ROLE=<KEYCLOAK_ADMIN_ROLE>
    PUBLIC_ROLE=<KEYCLOAK_PUBLIC_ROLE>
    KEYCLOAK_BASE_URL=<KEYCLOAK_BASE_URL>
    KEYCLOAK_REALM=<KEYCLOAK_REALM>

ADMIN_ROLE : will have complete access to superset.(Admin role of superset)
PUBLIC_ROLE: will have access for viewing the dashboard(Alpha role of superset)

***Note**: While configuring keycloak relam please make sure that userInfo API of keycloak realm should return role of the users as well.*
## Deployment

Just download this repository. install docker in system and run below command:

    docker-compose up
For detailed explanation  [Superset Deployment](https://superset.apache.org/docs/installation/installing-superset-using-docker-compose) documentations can be followed.
 
