use actix_files::NamedFile;
use actix_web::{get, web, App, HttpServer, Responder, Result};
use actix_web_actors::ws;
use crossbeam_channel::{Receiver, Sender};
use lazy_static::lazy_static;
use log::info;
use rustreaper::models::Artifact;
use serde_json::to_string;
use sqlite::Connection;
use std::path::PathBuf;
use std::sync::Mutex;

lazy_static! {
    static ref PROGRESS_CHANNEL: Mutex<Option<(Sender<f32>, Sender<f32>)>> = Mutex::new(None);
}

#[derive(serde::Serialize)]
struct ProgressMessage {
    parse_progress: f32,
    analyze_progress: f32,
    artifact_count: usize,
}

struct WsSession {
    progress_rx: (Receiver<f32>, Receiver<f32>),
    db_path: PathBuf,
}

impl actix_web_actors::Actor for WsSession {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let (parse_rx, analyze_rx) = self.progress_rx.clone();
        let db_path = self.db_path.clone();
        ctx.run_interval(std::time::Duration::from_millis(500), move |act, ctx| {
            let mut parse_progress = parse_rx.try_recv().unwrap_or(0.0);
            let mut analyze_progress = analyze_rx.try_recv().unwrap_or(0.0);
            let artifact_count = {
                let conn = Connection::open(&db_path).unwrap();
                let mut stmt = conn.prepare("SELECT COUNT(*) FROM artifacts").unwrap();
                stmt.query(()).unwrap().next().unwrap().get(0).unwrap()
            };
            ctx.text(to_string(&ProgressMessage {
                parse_progress,
                analyze_progress,
                artifact_count,
            }).unwrap());
        });
    }
}

impl ws::StreamHandler<Result<ws::Message, ws::ProtocolError>> for WsSession {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        if let Ok(ws::Message::Ping(msg)) = msg {
            ctx.pong(&msg);
        }
    }
}

#[get("/ws")]
async fn websocket(ws: web::WebSocket, stream: web::Payload, data: web::Data<PathBuf>) -> Result<impl Responder> {
    let progress_rx = PROGRESS_CHANNEL.lock().unwrap()
        .as_ref()
        .map(|(parse_tx, analyze_tx)| (parse_tx.subscribe(), analyze_tx.subscribe()))
        .unwrap_or_else(|| (unbounded::<f32>().1, unbounded::<f32>().1));
    ws::start(WsSession {
        progress_rx,
        db_path: data.to_path_buf(),
    }, &ws, stream)
}

#[get("/")]
async fn index() -> Result<NamedFile> {
    Ok(NamedFile::open("../web/index.html")?)
}

#[get("/api/artifacts")]
async fn get_artifacts(db_path: web::Data<PathBuf>) -> impl Responder {
    let conn = Connection::open(db_path.as_path()).unwrap();
    let mut stmt = conn.prepare("SELECT data FROM artifacts").unwrap();
    let rows = stmt.query(()).unwrap();
    let mut artifacts = Vec::new();
    for row in rows {
        let data: String = row.get(0).unwrap();
        let artifact: Artifact = serde_json::from_str(&data).unwrap();
        artifacts.push(artifact);
    }
    web::Json(artifacts)
}

#[get("/api/report")]
async fn download_report(db_path: web::Data<PathBuf>) -> impl Responder {
    let conn = Connection::open(db_path.as_path()).unwrap();
    let mut stmt = conn.prepare("SELECT data FROM artifacts").unwrap();
    let rows = stmt.query(()).unwrap();
    let mut artifacts = Vec::new();
    for row in rows {
        let data: String = row.get(0).unwrap();
        let artifact: Artifact = serde_json::from_str(&data).unwrap();
        artifacts.push(artifact);
    }
    let json = to_string(&artifacts).unwrap();
    web::Bytes::from(json)
        .customize()
        .with_header(("Content-Disposition", "attachment; filename=report.json"))
}

pub async fn start_server(addr: &str, auth: bool, db_path: &PathBuf) -> std::io::Result<()> {
    info!("Serving GUI at http://{} (auth: {})", addr, auth);
    HttpServer::new(move || {
        let app = App::new()
            .app_data(web::Data::new(db_path.clone()))
            .service(index)
            .service(get_artifacts)
            .service(download_report)
            .service(websocket)
            .service(actix_files::Files::new("/static", "../web/static"));
        if auth {
            info!("Authentication enabled (not implemented)");
            app
        } else {
            app
        }
    })
    .bind(addr)?
    .run()
    .await
}