#![cfg(feature = "seaorm2")]
#![allow(
    unreachable_pub,
    reason = "SeaORM entity derives require public generated model types"
)]

#[path = "../compat-tests/rust-server/src/organization_fields.rs"]
mod fixture;

use better_auth::__private_core::{
    store::OrganizationStore,
    types::{CreateOrganization, UpdateOrganization},
};
use better_auth::plugins::organization::OrganizationConfig;
use better_auth::seaorm::{Database, SeaOrmStore, sea_orm::EntityTrait};
use better_auth_seaorm::store::__private_test_support::{
    bundled_schema::BundledSchema, migrator::run_migrations,
};
use serde_json::json;

#[tokio::test]
async fn field_names_accept_rust_and_serde_aliases_without_losing_or_repeating_transforms() {
    for field_name in ["stored_label", "storedLabel"] {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        run_migrations(&db).await.unwrap();
        fixture::create_tables(&db).await.unwrap();
        let mut options = OrganizationConfig::default();
        fixture::configure(&mut options);
        options
            .schema
            .organization
            .fields_mut()
            .get_mut("label")
            .unwrap()
            .field_name = Some(field_name.into());
        let store = SeaOrmStore::<BundledSchema>::new(
            better_auth::AuthConfig::new("organization-alias-secret-at-least-32-chars"),
            db.clone(),
        )
        .with_organization_schema::<fixture::models::Models>();
        store.configure_organization_fields(options.schema).unwrap();

        let mut create = CreateOrganization::new("Alias organization", "alias");
        let _ = create
            .additional_fields
            .insert("label".into(), json!("original"));
        let organization = store.create_organization(create).await.unwrap();
        assert_eq!(organization.additional_fields["label"], "original:in:out");
        let restored = store
            .get_organization_by_id(organization.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored.additional_fields["label"], "original:in:out");

        let updated = store
            .update_organization(
                organization.id.typed().unwrap(),
                UpdateOrganization {
                    additional_fields: [("label".into(), json!("changed"))].into_iter().collect(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.additional_fields["label"], "changed:in:out");
        let raw =
            fixture::models::organization::Entity::find_by_id(organization.id.typed().unwrap())
                .one(&db)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(raw.stored_label.as_deref(), Some("changed:in"));
        fixture::reset(&db).await.unwrap();
    }
}
