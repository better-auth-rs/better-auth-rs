// Upstream mergeSchema mutates module-level plugin schemas. Keep each capture's initial state independent of test order.
export async function withRestoredSchema(schema, operation) {
  const objects = [schema, ...Object.values(schema).flatMap(model => [model, model.fields, ...Object.values(model.fields)])];
  const snapshots = objects.map(object => [object, Object.getOwnPropertyDescriptors(object)]);
  try {
    return await operation();
  } finally {
    for (const [object, descriptors] of snapshots) {
      for (const key of Reflect.ownKeys(object)) {
        if (!Object.hasOwn(descriptors, key)) delete object[key];
      }
      Object.defineProperties(object, descriptors);
    }
  }
}
