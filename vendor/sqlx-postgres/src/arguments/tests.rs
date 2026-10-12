use super::*;

#[test]
fn text_and_binary_arguments_retain_type_format_null_and_bytes() {
    let mut arguments = PgArguments::default();
    arguments.add("1").unwrap();
    arguments.add_text(Some("1")).unwrap();
    arguments.add(7_i32).unwrap();
    arguments.add_text(None).unwrap();

    assert_eq!(arguments.len(), 4);
    assert_eq!(
        arguments
            .types
            .iter()
            .map(PgTypeInfo::oid)
            .collect::<Vec<_>>(),
        [Some(Oid(25)), Some(Oid(0)), Some(Oid(23)), Some(Oid(0))]
    );
    assert_eq!(
        arguments.formats,
        [
            PgValueFormat::Binary,
            PgValueFormat::Text,
            PgValueFormat::Binary,
            PgValueFormat::Text,
        ]
    );
    assert_eq!(
        &*arguments.buffer,
        b"\0\0\0\x011\0\0\0\x011\0\0\0\x04\0\0\0\x07\xff\xff\xff\xff"
    );
}

#[derive(Debug)]
struct EncodingFailure(Arc<()>);

impl fmt::Display for EncodingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected encoding failure")
    }
}

impl std::error::Error for EncodingFailure {}

struct FailingEncoder(Arc<()>);

impl Type<Postgres> for FailingEncoder {
    fn type_info() -> PgTypeInfo {
        PgTypeInfo::INT4
    }
}

impl Encode<'_, Postgres> for FailingEncoder {
    fn encode_by_ref(&self, buffer: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        buffer.extend_from_slice(b"partial");
        buffer.patch(|_, _| panic!("failed parameter patch must be discarded"));
        buffer.patch_type_by_name(&UStr::Static("discarded_type"));
        Err(Box::new(EncodingFailure(self.0.clone())))
    }
}

#[test]
fn failed_encoding_preserves_original_error_and_allows_more_parameters() {
    let mut arguments = PgArguments::default();
    arguments.add_text(Some("before")).unwrap();
    arguments.add(7_i32).unwrap();
    let before = arguments.clone();
    let error_identity = Arc::new(());

    let error = arguments
        .add(FailingEncoder(error_identity.clone()))
        .unwrap_err();

    assert!(Arc::ptr_eq(
        &error.downcast_ref::<EncodingFailure>().unwrap().0,
        &error_identity
    ));
    assert_eq!(arguments.types, before.types);
    assert_eq!(arguments.formats, before.formats);
    assert_eq!(arguments.buffer.buffer, before.buffer.buffer);
    assert_eq!(arguments.buffer.count, before.buffer.count);
    assert!(arguments.buffer.patches.is_empty());
    assert!(arguments.buffer.type_holes.is_empty());

    arguments.add_text(None).unwrap();
    arguments.add(9_i32).unwrap();
    assert_eq!(arguments.len(), 4);
    assert_eq!(
        arguments.formats[2..],
        [PgValueFormat::Text, PgValueFormat::Binary]
    );
    assert_eq!(arguments.types[2].oid(), Some(Oid(0)));
    assert_eq!(arguments.types[3].oid(), Some(Oid(23)));
    assert_eq!(
        &arguments.buffer[before.buffer.len()..],
        b"\xff\xff\xff\xff\0\0\0\x04\0\0\0\x09"
    );
}
