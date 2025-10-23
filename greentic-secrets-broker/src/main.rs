#[tokio::main]
async fn main() -> anyhow::Result<()> {
    secrets_broker::run().await
}
