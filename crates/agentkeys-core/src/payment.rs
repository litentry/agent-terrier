use agentkeys_types::{
    Amount, PaymentLayer, SpendEvent, SpendFilter, TransactionReceipt, WalletAddress,
};
use async_trait::async_trait;

use crate::backend::BackendError;

#[async_trait]
pub trait PaymentRail: Send + Sync {
    async fn check_balance(
        &self,
        wallet: &WalletAddress,
        amount: Amount,
        layer: PaymentLayer,
    ) -> Result<bool, BackendError>;

    async fn debit(
        &self,
        wallet: &WalletAddress,
        amount: Amount,
        layer: PaymentLayer,
        reason: &str,
    ) -> Result<TransactionReceipt, BackendError>;

    async fn fund_child(
        &self,
        master: &WalletAddress,
        child: &WalletAddress,
        amount: Amount,
        layer: PaymentLayer,
    ) -> Result<TransactionReceipt, BackendError>;

    async fn spending_history(
        &self,
        wallet: &WalletAddress,
        filter: SpendFilter,
    ) -> Result<Vec<SpendEvent>, BackendError>;

    fn display_name(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use agentkeys_types::PaymentLayer;

    #[test]
    fn layer_enum() {
        assert_ne!(PaymentLayer::SystemGas, PaymentLayer::ServicePayment);
        assert_eq!(PaymentLayer::SystemGas, PaymentLayer::SystemGas);
        assert_eq!(PaymentLayer::ServicePayment, PaymentLayer::ServicePayment);
    }
}
