use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("octobroker=info".parse().unwrap()),
        )
        .with_timer(tracing_subscriber::fmt::time::LocalTime::new(
            time::format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second]")
                .unwrap(),
        ))
        .init();

    octobroker::run().await;
}
