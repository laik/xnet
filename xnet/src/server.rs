use std::sync::Arc;

use anyhow::Context as _;
use aya::programs::SchedClassifier;
use aya::programs::{SchedClassifier as Tc, TcAttachType};
use hyper::{
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server, StatusCode,
};
use serde_json;
use tokio::sync::Mutex;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
enum Action {
    Add = 1,
    Remove = 2,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct MonitorRequest {
    iface: String,
    action: Action,
}

async fn heartbeat() -> Result<Response<Body>, hyper::Error> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("ok"))
        .unwrap())
}

async fn handle_monitor_device(
    tc: &mut SchedClassifier,
    req: Request<Body>,
) -> Result<Response<Body>, hyper::Error> {
    if req.method() != Method::POST {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::from("Method not allowed"))
            .unwrap());
    }

    let whole_body = hyper::body::to_bytes(req.into_body()).await?;
    println!("收到请求: {}", String::from_utf8_lossy(&whole_body));

    match serde_json::from_slice::<MonitorRequest>(&whole_body) {
        Ok(request) => {
            println!(
                "处理请求: iface={}, action={:?}",
                request.iface, request.action
            );

            match request.action {
                Action::Add => {
                    // 检查接口是否存在
                    if !std::path::Path::new(&format!("/sys/class/net/{}", request.iface)).exists()
                    {
                        println!("错误: 接口 {} 不存在", request.iface);
                        return Ok(Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Body::from(format!(
                                "Interface {} does not exist",
                                request.iface
                            )))
                            .unwrap());
                    }

                    // 检查是否已经有TC程序附加到该接口
                    let tc_check_path = format!("/sys/fs/bpf/tc/globals/xnet_tc_{}", request.iface);
                    if std::path::Path::new(&tc_check_path).exists() {
                        println!("警告: TC程序已经附加到接口 {}，跳过附加操作", request.iface);
                        return Ok(Response::builder()
                            .status(StatusCode::OK)
                            .body(Body::from("TC program already attached"))
                            .unwrap());
                    }

                    // 使用超时机制防止卡住
                    let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                        println!("正在附加TC程序到接口 {}...", request.iface);
                        if let Err(e) = tc
                            .attach(&request.iface, TcAttachType::Ingress)
                            .context("failed to attach the TC program")
                        {
                            println!("错误: 附加TC程序失败: {}", e);
                            return Err(format!("Failed to attach TC program: {}", e));
                        }

                        println!("成功附加TC程序到接口 {}", request.iface);
                        Ok(())
                    })
                    .await;

                    match result {
                        Ok(Ok(())) => {
                            println!("操作成功完成");
                            Ok(Response::builder()
                                .status(StatusCode::OK)
                                .body(Body::from("ok"))
                                .unwrap())
                        }
                        Ok(Err(e)) => {
                            println!("操作失败: {}", e);
                            Ok(Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::from(format!("Operation failed: {}", e)))
                                .unwrap())
                        }
                        Err(_) => {
                            println!("操作超时");
                            Ok(Response::builder()
                                .status(StatusCode::REQUEST_TIMEOUT)
                                .body(Body::from("Operation timeout"))
                                .unwrap())
                        }
                    }
                }
                Action::Remove => {
                    println!("Remove action - 目前只是返回成功");
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from("ok"))
                        .unwrap())
                }
            }
        }
        Err(e) => {
            println!("JSON解析错误: {}", e);
            Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(format!("Invalid JSON: {}", e)))
                .unwrap())
        }
    }
}

async fn handle_request(
    tc: &mut SchedClassifier,
    req: Request<Body>,
) -> Result<Response<Body>, hyper::Error> {
    match req.uri().path() {
        "/" => heartbeat().await,
        "/monitor_device" => handle_monitor_device(tc, req).await,
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not found"))
            .unwrap()),
    }
}

pub async fn start_server(tc: &'static mut SchedClassifier) -> Result<(), hyper::Error> {
    // 启动 HTTP 服务
    let addr = ([0, 0, 0, 0], 8080).into();
    let tc = Arc::new(Mutex::new(tc));
    let make_svc = make_service_fn(move |_conn| {
        let tc = tc.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let tc = tc.clone();
                async move {
                    let mut tc = tc.lock().await;
                    handle_request(&mut tc, req).await
                }
            }))
        }
    });
    let server = Server::bind(&addr).serve(make_svc);
    println!("HTTP 服务器启动在 http://0.0.0.0:8080");
    server.await?;
    Ok(())
}
