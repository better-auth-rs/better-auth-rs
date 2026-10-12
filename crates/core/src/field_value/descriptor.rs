//! Complete property slots and partial definitions preserve absence without evaluating accessors.

use super::{FieldFunction, FieldValue};
use crate::AuthResult;

/// The value or accessors stored in one own property.
#[derive(Clone, Debug, PartialEq)]
pub enum FieldProperty {
    /// A stored value with an independent assignment permission.
    Data {
        /// The current native value.
        value: FieldValue,
        /// Whether assignment may replace the value.
        writable: bool,
    },
    /// Native functions invoked with the original receiver.
    Accessor {
        /// An absent getter returns undefined.
        get: Option<FieldFunction>,
        /// An absent setter rejects assignment.
        set: Option<FieldFunction>,
    },
}

/// A complete own-property descriptor. Inspection never invokes an accessor.
#[derive(Clone, Debug, PartialEq)]
pub struct FieldPropertyDescriptor {
    /// Whether enumeration selects the property.
    pub enumerable: bool,
    /// Whether deletion and descriptor-kind changes are permitted.
    pub configurable: bool,
    /// The data or accessor slot.
    pub property: FieldProperty,
}

/// The supplied part of a property definition.
#[derive(Clone, Debug, Default)]
pub enum FieldPropertyUpdate {
    /// Change only the supplied common attributes.
    #[default]
    Generic,
    /// Missing data attributes preserve the existing values.
    Data {
        /// `None` omits the value; `Some(Undefined)` explicitly supplies undefined.
        value: Option<FieldValue>,
        /// `None` preserves the existing assignment permission.
        writable: Option<bool>,
    },
    /// Missing accessor attributes preserve the existing functions.
    Accessor {
        /// `None` omits the getter; `Some(None)` removes the getter.
        get: Option<Option<FieldFunction>>,
        /// `None` omits the setter; `Some(None)` removes the setter.
        set: Option<Option<FieldFunction>>,
    },
}

/// A partial definition distinguishes omitted attributes from explicit false or undefined.
#[derive(Clone, Debug, Default)]
pub struct FieldPropertyDefinition {
    /// `None` preserves the existing enumeration attribute.
    pub enumerable: Option<bool>,
    /// `None` preserves the existing reconfiguration attribute.
    pub configurable: Option<bool>,
    /// The supplied data or accessor attributes.
    pub property: FieldPropertyUpdate,
}

impl FieldPropertyDescriptor {
    /// Create the writable, enumerable, configurable data slot used by assignment and object literals.
    pub fn data(value: FieldValue) -> Self {
        Self {
            enumerable: true,
            configurable: true,
            property: FieldProperty::Data {
                value,
                writable: true,
            },
        }
    }

    pub(crate) fn read(&self, receiver: &FieldValue) -> AuthResult<FieldValue> {
        match &self.property {
            FieldProperty::Data { value, .. } => Ok(value.clone()),
            FieldProperty::Accessor { get: Some(get), .. } => get.call_with(receiver, &[]),
            FieldProperty::Accessor { get: None, .. } => Ok(FieldValue::Undefined),
        }
    }

    pub(crate) fn assign(
        &self,
        receiver: &FieldValue,
        value: FieldValue,
    ) -> AuthResult<Option<bool>> {
        match &self.property {
            FieldProperty::Data { writable, .. } => Ok((!*writable).then_some(false)),
            FieldProperty::Accessor { set: Some(set), .. } => {
                let _ = set.call_with(receiver, &[value])?;
                Ok(Some(true))
            }
            FieldProperty::Accessor { set: None, .. } => Ok(Some(false)),
        }
    }
}

impl FieldPropertyDefinition {
    /// Define only a new data value, preserving the other attributes of an existing property.
    pub fn value(value: FieldValue) -> Self {
        Self {
            property: FieldPropertyUpdate::Data {
                value: Some(value),
                writable: None,
            },
            ..Self::default()
        }
    }

    /// Validate and complete the definition without reading or invoking a property value.
    /// `None` means that the current descriptor rejects the definition.
    pub(crate) fn apply(
        &self,
        current: Option<&FieldPropertyDescriptor>,
    ) -> Option<FieldPropertyDescriptor> {
        let property = match &self.property {
            FieldPropertyUpdate::Data {
                value: None,
                writable: None,
            }
            | FieldPropertyUpdate::Accessor {
                get: None,
                set: None,
            } => &FieldPropertyUpdate::Generic,
            property => property,
        };
        let Some(current) = current else {
            let property = match property {
                FieldPropertyUpdate::Generic => FieldProperty::Data {
                    value: FieldValue::Undefined,
                    writable: false,
                },
                FieldPropertyUpdate::Data { value, writable } => FieldProperty::Data {
                    value: value.clone().unwrap_or_default(),
                    writable: writable.unwrap_or(false),
                },
                FieldPropertyUpdate::Accessor { get, set } => FieldProperty::Accessor {
                    get: get.clone().flatten(),
                    set: set.clone().flatten(),
                },
            };
            return Some(FieldPropertyDescriptor {
                enumerable: self.enumerable.unwrap_or(false),
                configurable: self.configurable.unwrap_or(false),
                property,
            });
        };
        if !current.configurable {
            if self.configurable == Some(true)
                || self
                    .enumerable
                    .is_some_and(|value| value != current.enumerable)
            {
                return None;
            }
            match (&current.property, property) {
                (
                    FieldProperty::Data {
                        writable: false,
                        value: before,
                    },
                    FieldPropertyUpdate::Data { value, writable },
                ) => {
                    if *writable == Some(true)
                        || value
                            .as_ref()
                            .is_some_and(|value| !value.same_value(before))
                    {
                        return None;
                    }
                }
                (
                    FieldProperty::Accessor {
                        get: before_get,
                        set: before_set,
                    },
                    FieldPropertyUpdate::Accessor { get, set },
                ) => {
                    if get.as_ref().is_some_and(|value| value != before_get)
                        || set.as_ref().is_some_and(|value| value != before_set)
                    {
                        return None;
                    }
                }
                (FieldProperty::Data { .. }, FieldPropertyUpdate::Accessor { .. })
                | (FieldProperty::Accessor { .. }, FieldPropertyUpdate::Data { .. }) => {
                    return None;
                }
                _ => {}
            }
        }
        let property = match (&current.property, property) {
            (property, FieldPropertyUpdate::Generic) => property.clone(),
            (before, FieldPropertyUpdate::Data { value, writable }) => {
                let (before_value, before_writable) = match before {
                    FieldProperty::Data { value, writable } => (value.clone(), *writable),
                    FieldProperty::Accessor { .. } => (FieldValue::Undefined, false),
                };
                FieldProperty::Data {
                    value: value.clone().unwrap_or(before_value),
                    writable: writable.unwrap_or(before_writable),
                }
            }
            (before, FieldPropertyUpdate::Accessor { get, set }) => {
                let (before_get, before_set) = match before {
                    FieldProperty::Accessor { get, set } => (get.clone(), set.clone()),
                    FieldProperty::Data { .. } => (None, None),
                };
                FieldProperty::Accessor {
                    get: get.clone().unwrap_or(before_get),
                    set: set.clone().unwrap_or(before_set),
                }
            }
        };
        Some(FieldPropertyDescriptor {
            enumerable: self.enumerable.unwrap_or(current.enumerable),
            configurable: self.configurable.unwrap_or(current.configurable),
            property,
        })
    }
}

impl From<FieldPropertyDescriptor> for FieldPropertyDefinition {
    fn from(descriptor: FieldPropertyDescriptor) -> Self {
        Self {
            enumerable: Some(descriptor.enumerable),
            configurable: Some(descriptor.configurable),
            property: match descriptor.property {
                FieldProperty::Data { value, writable } => FieldPropertyUpdate::Data {
                    value: Some(value),
                    writable: Some(writable),
                },
                FieldProperty::Accessor { get, set } => FieldPropertyUpdate::Accessor {
                    get: Some(get),
                    set: Some(set),
                },
            },
        }
    }
}
