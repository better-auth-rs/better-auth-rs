use better_auth_core::{AuthResult, AuthSchema, CreateVerification};

use super::{AuthError, SeaOrmStore, SeaOrmTransaction};
use crate::schema::SeaOrmVerificationModel;

pub(super) enum Effect<S: AuthSchema> {
    Created(S::Verification),
    Deleted(S::Verification),
}

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmTransaction<'_, S, O, P>
where
    S: AuthSchema,
    S::Verification: SeaOrmVerificationModel,
{
    pub(super) async fn create_transaction_verification(
        &self,
        input: CreateVerification,
    ) -> AuthResult<S::Verification> {
        let record = self
            .store
            .create_verification_with_connection(self.tx, Some(self.tx), input)
            .await?;
        self.verification_effects
            .lock()
            .map_err(|_| AuthError::internal("Verification transaction queue lock poisoned"))?
            .push(Effect::Created(record.clone()));
        Ok(record)
    }

    pub(super) async fn delete_expired_transaction_verifications(&self) -> AuthResult<usize> {
        let (count, records) = self
            .store
            .delete_expired_verifications_with_connection(self.tx, Some(self.tx))
            .await?;
        self.verification_effects
            .lock()
            .map_err(|_| AuthError::internal("Verification transaction queue lock poisoned"))?
            .extend(records.into_iter().map(Effect::Deleted));
        Ok(count)
    }
}

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::Verification: SeaOrmVerificationModel,
{
    pub(super) async fn finish_verification_effects(
        &self,
        effects: Vec<Effect<S>>,
    ) -> AuthResult<()> {
        let context = self.hook_context(None);
        for effect in effects {
            for hook in self.hooks() {
                match &effect {
                    Effect::Created(record) => {
                        hook.after_create_verification(record, &context).await?
                    }
                    Effect::Deleted(record) => {
                        hook.after_delete_verification(record, &context).await?
                    }
                }
            }
        }
        Ok(())
    }
}
