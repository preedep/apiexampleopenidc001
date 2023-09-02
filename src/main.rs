use actix_web::{App, get, HttpRequest, HttpResponse, HttpServer, Responder, web};
use actix_web::http::header;
use actix_web::web::Data;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use serde_json::json;


///
/// Open ID Configuration
///
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenIDConfigurationV2 {
    #[serde(rename = "token_endpoint")]
    pub token_endpoint: Option<String>,
    #[serde(rename = "token_endpoint_auth_methods_supported")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(rename = "jwks_uri")]
    pub jwks_uri: Option<String>,
    #[serde(rename = "response_modes_supported")]
    pub response_modes_supported: Option<Vec<String>>,
    #[serde(rename = "subject_types_supported")]
    pub subject_types_supported: Option<Vec<String>>,
    #[serde(rename = "id_token_signing_alg_values_supported")]
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(rename = "response_types_supported")]
    pub response_types_supported: Option<Vec<String>>,
    #[serde(rename = "scopes_supported")]
    pub scopes_supported: Option<Vec<String>>,
    pub issuer: Option<String>,
    #[serde(rename = "request_uri_parameter_supported")]
    pub request_uri_parameter_supported: Option<bool>,
    #[serde(rename = "userinfo_endpoint")]
    pub userinfo_endpoint: Option<String>,
    #[serde(rename = "authorization_endpoint")]
    pub authorization_endpoint: Option<String>,
    #[serde(rename = "device_authorization_endpoint")]
    pub device_authorization_endpoint: Option<String>,
    #[serde(rename = "http_logout_supported")]
    pub http_logout_supported: Option<bool>,
    #[serde(rename = "frontchannel_logout_supported")]
    pub frontchannel_logout_supported: Option<bool>,
    #[serde(rename = "end_session_endpoint")]
    pub end_session_endpoint: Option<String>,
    #[serde(rename = "claims_supported")]
    pub claims_supported: Option<Vec<String>>,
    #[serde(rename = "kerberos_endpoint")]
    pub kerberos_endpoint: Option<String>,
    #[serde(rename = "tenant_region_scope")]
    pub tenant_region_scope: Option<String>,
    #[serde(rename = "cloud_instance_name")]
    pub cloud_instance_name: Option<String>,
    #[serde(rename = "cloud_graph_host_name")]
    pub cloud_graph_host_name: Option<String>,
    #[serde(rename = "msgraph_host")]
    pub msgraph_host: Option<String>,
    #[serde(rename = "rbac_url")]
    pub rbac_url: Option<String>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JWKS {
    pub keys: Option<Vec<JWKSKeyItem>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JWKSKeyItem {
    pub kty: Option<String>,
    #[serde(rename = "use")]
    pub use_field: Option<String>,
    pub kid: Option<String>,
    pub x5t: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    pub x5c: Option<Vec<String>>,
    pub issuer: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub redis_url: String,
    pub redis_auth_key: String,
    pub tenant_id: String,
    pub default_page: String,
    pub redirect: String,
    pub client_id: String,
    pub client_secret: String,
    pub open_id_config: Option<OpenIDConfigurationV2>,
    pub jwks: Option<JWKS>
}

impl Config {
    pub fn new(
        redis_url: String,
        redis_auth_key: String,
        tenant_id: String,
        default_page: String,
        redirect: String,
        client_id: String,
        client_secret: String,
    ) -> Self {
        Config {
            redis_url,
            redis_auth_key,
            tenant_id,
            default_page,
            redirect,
            client_id,
            client_secret,
            open_id_config: None,
            jwks: None,
        }
    }
}
async fn ping(request: HttpRequest,data: web::Data<Config>) -> impl Responder {
    debug!("Request was sent at {:#?}", request.headers());
    HttpResponse::Ok().json(json!({
        "message":"pong"
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    pretty_env_logger::init();

    //
    //  Load environment variable
    //
    let redis_url = std::env::var("REDIS_URL").unwrap_or("".to_string());
    let redis_auth_key = std::env::var("REDIS_AUTH_KEY").unwrap_or("".to_string());
    let tenant_id = std::env::var("TENANT_ID").unwrap_or("".to_string());
    let default_page = std::env::var("DEFAULT_PAGE").unwrap_or("".to_string());
    let redirect_url = std::env::var("REDIRECT_URL").unwrap_or("".to_string());
    let client_id = std::env::var("CLIENT_ID").unwrap_or("".to_string());
    let client_secret = std::env::var("CLIENT_SECRET").unwrap_or("".to_string());
    let cookie_ssl = std::env::var("COOKIE_SSL").unwrap_or("false".to_string());

    let use_cookie_ssl: bool = match cookie_ssl.as_str() {
        "false" => false,
        "true" => true,
        _ => false,
    };

    let mut config = Config::new(
        redis_url,
        redis_auth_key,
        tenant_id,
        default_page,
        redirect_url,
        client_id,
        client_secret,
    );
    //
    // Get azure ad meta data
    //
    let url_openid_config = format!(
        r#"https://login.microsoftonline.com/{:1}/v2.0/.well-known/openid-configuration?appid={:2}"#,
        config.to_owned().tenant_id,
        config.to_owned().client_id
    );
    info!("url validation : {}", url_openid_config);
    let meta_azure_ad = reqwest::get(url_openid_config)
        .await
        .unwrap()
        .json::<OpenIDConfigurationV2>()
        .await;
    match meta_azure_ad {
        Ok(cnf) => {
            debug!("Meta data : {:#?}", cnf);
            config.open_id_config = Some(cnf);
            let jwks_uri = config.open_id_config.clone().unwrap().jwks_uri.unwrap();
            let jwks_items = reqwest::get(jwks_uri)
                .await
                .unwrap()
                .json::<JWKS>().await;
            match jwks_items {
                Ok(jwks) => {
                    debug!("JWKS = {:#?}",jwks);
                    config.jwks = Some(jwks.clone());
                }
                Err(e) => {
                    error!("Get jwks error : {}", e);
                }
            }
        }
        Err(e) => {
            error!("Get meta error : {}", e);
        }
    }
    HttpServer::new(move || {
        // move counter into the closure
        App::new()
            .app_data(Data::new(config.clone()))
            .route("/ping", web::get().to(ping))
    })
        .bind(("0.0.0.0", 8081))?
        .run()
        .await
}