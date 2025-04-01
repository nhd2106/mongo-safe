import { UnsafePattern } from "../types";

/**
 * Collection of unsafe MongoDB query patterns that could lead to vulnerabilities
 */
export const unsafePatterns: UnsafePattern[] = [
  {
    id: "FUNCTION_PARAMETER_INJECTION",
    name: "Function Parameter Injection",
    pattern:
      /\.(find|findOne|aggregate|update|delete)\s*\(\s*\{\s*[a-zA-Z0-9_]+\s*:\s*(\w+)(?!\()/i,
    description:
      "Using unvalidated function parameters directly in queries can lead to query injection attacks",
    severity: "high",
    suggestion:
      "Validate and sanitize all function parameters before using them in database queries. Consider using schema validation or type checking.",
    example: "const getUser = (username) => db.users.find({ username });",
    safeExample:
      "const getUser = (username) => {\n  if (typeof username !== 'string' || !username) throw new Error('Invalid username');\n  return db.users.find({ username });\n};",
    docUrl:
      "https://www.mongodb.com/docs/manual/core/security-input-validation/",
  },
  {
    id: "TEMPLATE_STRING_INJECTION",
    name: "Template String Injection",
    pattern:
      /db\.[a-zA-Z0-9_]+\.(find|findOne|aggregate|update|delete)\s*\(\s*\`.*?\$\{.*?\}.*?\`/i,
    description:
      "Using template literals with interpolated values in MongoDB queries can lead to injection attacks",
    severity: "high",
    suggestion:
      "Never use template literals to construct MongoDB queries. Use parameterized objects instead.",
    example: 'db.users.find(`{ username: "${username}" }`);',
    safeExample: "db.users.find({ username: sanitizedUsername });",
    docUrl:
      "https://www.mongodb.com/docs/manual/faq/fundamentals/#how-does-mongodb-address-sql-or-query-injection",
  },
  {
    id: "ARRAY_FILTER_INJECTION",
    name: "Array Filter Injection",
    pattern: /\$\[\s*\w+\s*\]/i,
    description:
      "Using unvalidated identifiers in array filters can lead to query injection",
    severity: "medium",
    suggestion:
      "Validate array filter identifiers and ensure they only contain alphanumeric characters",
    example:
      "db.collection.updateOne({}, { $set: { 'items.$[userInput]': newValue } });",
    safeExample:
      "const filterId = /^[a-zA-Z0-9]+$/.test(userInput) ? userInput : 'default';\ndb.collection.updateOne({}, { $set: { [`items.$[${filterId}]`]: newValue } });",
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/operator/update/positional-filtered/",
  },
  {
    id: "DIRECT_QUERY_VARIABLE_ASSIGNMENT",
    name: "Direct Query Variable Assignment",
    pattern: /const\s+query\s*=\s*req\.(body|params|query)/i,
    description:
      "Directly assigning request data to a query variable can lead to query injection",
    severity: "high",
    suggestion:
      "Never assign user input directly to query objects. Always construct queries with validated fields.",
    example: "const query = req.query;\ndb.users.find(query);",
    safeExample:
      "const { name, email } = validateUserInput(req.query);\ndb.users.find({ name, email });",
    docUrl:
      "https://www.mongodb.com/docs/manual/core/security-input-validation/",
  },
  {
    id: "BULK_OPERATION_INJECTION",
    name: "Bulk Operation Injection",
    pattern: /\.bulkWrite\s*\(\s*(\w+)(?!\()/i,
    description:
      "Using unvalidated input in bulk operations can lead to mass data manipulation",
    severity: "high",
    suggestion:
      "Validate each operation in a bulk write array before execution",
    example: "db.collection.bulkWrite(userOperations);",
    safeExample:
      "const validatedOps = validateBulkOperations(userOperations);\nif (validatedOps) db.collection.bulkWrite(validatedOps);",
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/method/db.collection.bulkWrite/",
  },
  {
    id: "EVAL_USAGE",
    name: "Eval Usage",
    pattern: /db\.eval\s*\(/i,
    description:
      "Using db.eval() is deprecated and extremely dangerous as it allows arbitrary JavaScript execution",
    severity: "high",
    suggestion:
      "Never use db.eval(). Use aggregation framework or other MongoDB features instead.",
    example: "db.eval('function() { return db.users.findOne(); }');",
    safeExample: "db.users.findOne();",
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/method/db.eval/#security",
  },
  {
    id: "INSECURE_AUTH_CHECKS",
    name: "Insecure Authentication Checks",
    pattern: /\.(find|findOne)\s*\(\s*\{\s*.*?password.*?\}\s*\)/i,
    description:
      "Performing authentication through find operations can expose passwords or allow bypass",
    severity: "high",
    suggestion:
      "Use secure authentication mechanisms like Passport.js or MongoDB's built-in auth. Never query passwords directly.",
    example: "db.users.findOne({ username, password: plainTextPassword });",
    safeExample:
      "const user = await db.users.findOne({ username });\nconst isMatch = await bcrypt.compare(password, user.passwordHash);",
    docUrl: "https://www.mongodb.com/docs/manual/core/security-scram/",
  },
  {
    id: "WEAK_INDEXING",
    name: "Weak Indexing",
    pattern:
      /createIndex\s*\(\s*\{\s*.*?\s*\}\s*,\s*\{\s*(?!.*?unique).*?\}\s*\)/i,
    description:
      "Not using unique indexes for identity fields can lead to duplicate records and security issues",
    severity: "medium",
    suggestion:
      "Use unique indexes for identity fields like username, email, and account numbers",
    example: "db.users.createIndex({ email: 1 });",
    safeExample: "db.users.createIndex({ email: 1 }, { unique: true });",
    docUrl: "https://www.mongodb.com/docs/manual/core/index-unique/",
  },
  {
    id: "DIRECT_JSON_PARSE",
    name: "Direct JSON Parse to Query",
    pattern: /JSON\.parse\s*\(.*?\)\s*.*?(\.find|\.findOne|\.update|\.delete)/i,
    description:
      "Parsing JSON directly from external sources into queries can lead to injection attacks",
    severity: "high",
    suggestion:
      "Validate parsed JSON against a schema before using it in database operations",
    example: "const query = JSON.parse(queryString);\ndb.users.find(query);",
    safeExample:
      "const parsedData = JSON.parse(queryString);\nconst validatedQuery = validateQuerySchema(parsedData);\ndb.users.find(validatedQuery);",
    docUrl:
      "https://www.mongodb.com/docs/manual/faq/fundamentals/#how-does-mongodb-address-sql-or-query-injection",
  },
  {
    id: "TRANSACTION_WITHOUT_ERROR_HANDLING",
    name: "Transaction Without Error Handling",
    pattern: /startSession\s*\(\s*\).*?withTransaction.*?(?!\s*catch\s*\()/i,
    description:
      "MongoDB transactions without proper error handling can leave data in an inconsistent state",
    severity: "medium",
    suggestion:
      "Always use try/catch/finally blocks with transactions and implement proper error handling",
    example: "session.withTransaction(() => { /* operations */ });",
    safeExample:
      "try {\n  await session.withTransaction(async () => { /* operations */ });\n} catch (error) {\n  // Handle error and rollback if needed\n} finally {\n  await session.endSession();\n}",
    docUrl:
      "https://www.mongodb.com/docs/manual/core/transactions-in-applications/#error-handling",
  },
  {
    id: "NOSQL_INJECTION_OBJECT",
    name: "NoSQL Injection (Object)",
    pattern: /\{\s*(\$where|\$expr)\s*:/i,
    description:
      "Using $where or $expr operators can lead to NoSQL injection if user input is not properly sanitized",
    severity: "high",
    suggestion:
      "Validate and sanitize all user inputs. Avoid using $where or $expr with user input. Use specific field queries instead.",
    example:
      'db.users.find({ $where: "this.username === \'" + username + "\'" });',
    safeExample: "db.users.find({ username: sanitizedUsername });",
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/operator/query/where/#security",
  },
  {
    id: "NOSQL_INJECTION_REGEX",
    name: "NoSQL Injection (Regex)",
    pattern: /\{\s*['"a-zA-Z0-9_]+\s*:\s*new\s+RegExp\s*\(\s*.*?\s*\)/i,
    description:
      "Using RegExp with user input can lead to regex injection attacks or denial of service (ReDoS)",
    severity: "high",
    suggestion:
      "Validate the user input and ensure it doesn't contain regex special characters. Consider using exact matches instead.",
    example: "db.users.find({ username: new RegExp(userInput) });",
    safeExample: "db.users.find({ username: sanitizedUsername });",
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/operator/query/regex/#security",
  },
  {
    id: "NOSQL_INJECTION_STRING",
    name: "NoSQL Injection (String Concatenation)",
    pattern:
      /db\.[a-zA-Z0-9_]+\.(find|findOne|aggregate|update|delete)\s*\(\s*['"`]\s*\{\s*.*?\$.*?\}\s*['"`]\s*\+/i,
    description:
      "String concatenation to build query objects can lead to NoSQL injection",
    severity: "high",
    suggestion:
      "Never construct MongoDB queries using string concatenation. Use parameterized queries with proper objects.",
    example: 'db.users.find("{ username: \'" + username + "\' }");',
    safeExample: "db.users.find({ username: sanitizedUsername });",
    docUrl:
      "https://www.mongodb.com/docs/manual/faq/fundamentals/#how-does-mongodb-address-sql-or-query-injection",
  },
  {
    id: "UNVALIDATED_USER_INPUT",
    name: "Unvalidated User Input in Query",
    pattern:
      /\{\s*['"a-zA-Z0-9_]+\s*:\s*req\.body\.|req\.params\.|req\.query\./i,
    description:
      "Using unvalidated user input directly in queries can lead to NoSQL injection attacks",
    severity: "high",
    suggestion:
      "Always validate and sanitize user input before using it in database queries. Use validation libraries like Zod or Joi.",
    example: "db.users.find({ username: req.body.username });",
    safeExample:
      "const schema = z.object({ username: z.string() });\nconst { username } = schema.parse(req.body);\ndb.users.find({ username });",
    docUrl:
      "https://www.mongodb.com/docs/manual/core/security-input-validation/",
  },
  {
    id: "INSECURE_PROJECTION",
    name: "Insecure Projection",
    pattern:
      /\.(find|findOne)\s*\(\s*.*?\s*,\s*\{\s*(['"a-zA-Z0-9_]+\s*:\s*0|['"a-zA-Z0-9_]+\s*:\s*false)\s*\}/i,
    description:
      "Excluding fields in projection (using 0 or false) can unintentionally expose sensitive data",
    severity: "medium",
    suggestion:
      "Use positive projections (inclusion with 1) instead of negative projections (exclusion with 0) to explicitly specify which fields to return.",
    example: "db.users.find({}, { password: 0, secretKey: 0 });",
    safeExample: "db.users.find({}, { username: 1, email: 1 });",
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/operator/projection/positional/#security",
  },
  {
    id: "INSECURE_AGGREGATION",
    name: "Insecure Aggregation Pipeline",
    pattern:
      /\.aggregate\s*\(\s*\[\s*\{\s*\$project\s*:\s*\{.*?(\$literal|\$eval|\$function).*?\}\s*\}/i,
    description:
      "Using operators like $literal, $eval, or $function in aggregation pipelines with user input can lead to code injection",
    severity: "high",
    suggestion:
      "Avoid using $literal, $eval, or $function operators with user input. Validate and sanitize all input used in aggregation pipelines.",
    example:
      "db.users.aggregate([{ $project: { computed: { $eval: userInput } } }]);",
    safeExample:
      'db.users.aggregate([{ $project: { computed: { $sum: ["$field1", "$field2"] } } }]);',
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/operator/aggregation/project/#security",
  },
  {
    id: "UNCONSTRAINED_QUERY",
    name: "Unconstrained Query",
    pattern: /\.(find|findOne|update|delete)\s*\(\s*\{\s*\}\s*\)/i,
    description:
      "Querying without constraints can lead to retrieving or modifying all documents, potentially leaking sensitive data",
    severity: "medium",
    suggestion:
      "Always use specific query criteria to limit the scope of database operations.",
    example: "db.users.find({});",
    safeExample: 'db.users.find({ active: true, role: "user" });',
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/method/db.collection.find/#security",
  },
  {
    id: "MASS_ASSIGNMENT",
    name: "Mass Assignment Vulnerability",
    pattern:
      /\.(insertOne|insertMany|updateOne|updateMany|findOneAndUpdate)\s*\(\s*.*?,\s*\{\s*\$set\s*:\s*req\.body\s*\}/i,
    description:
      "Using the entire request body in updates can lead to mass assignment vulnerabilities",
    severity: "high",
    suggestion:
      "Explicitly select which fields from the request body should be updated. Never use the entire req.body object directly.",
    example: "db.users.updateOne({ _id }, { $set: req.body });",
    safeExample:
      "const { name, email } = req.body;\ndb.users.updateOne({ _id }, { $set: { name, email } });",
    docUrl:
      "https://www.mongodb.com/docs/manual/core/security-input-validation/",
  },
  {
    id: "INSECURE_INDEXING",
    name: "Insecure Text Indexing",
    pattern: /createIndex\s*\(\s*\{\s*.*?:\s*['"]text['"]\s*\}/i,
    description:
      "Text indices can be resource-intensive and susceptible to DoS attacks if not properly secured",
    severity: "medium",
    suggestion:
      "Limit text search queries, apply rate limiting, and ensure indices are created on specific fields only.",
    example: 'db.collection.createIndex({ content: "text" });',
    safeExample:
      'db.collection.createIndex({ title: "text" }, { weights: { title: 10 }, default_language: "english" });',
    docUrl:
      "https://www.mongodb.com/docs/manual/core/text-search-languages/#security",
  },
  {
    id: "UNAUTHORIZED_SCHEMA_MODIFICATION",
    name: "Unauthorized Schema Modification",
    pattern: /\.(createCollection|dropCollection|createIndex|dropIndex)\s*\(/i,
    description:
      "Schema modification operations should be restricted to administrative functions only",
    severity: "medium",
    suggestion:
      "Implement proper role-based access control for schema-modifying operations. Consider using migration scripts instead of runtime modifications.",
    example: 'db.createCollection("newCollection");',
    safeExample:
      "// Use a migration framework or limit this operation to admin routes with proper authorization",
    docUrl:
      "https://www.mongodb.com/docs/manual/core/security-operations/#security",
  },
  {
    id: "INSECURE_OPERATOR_USAGE",
    name: "Insecure Operator Usage",
    pattern: /\{\s*\$ne\s*:|"\$ne"\s*:|'\$ne'\s*:/i,
    description:
      "Using $ne operator can lead to authentication bypass if not properly secured",
    severity: "high",
    suggestion:
      "Be cautious when using negation operators. Ensure proper authentication checks and input validation.",
    example: 'db.users.find({ username: username, password: { $ne: "" } });',
    safeExample: "db.users.findOne({ username, password: hashedPassword });",
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/operator/query/ne/#security",
  },
  {
    id: "UNVALIDATED_ID",
    name: "Unvalidated MongoDB ObjectId",
    pattern: /(?<!isValid\()new\s+ObjectId\s*\(\s*.*?req\.(body|params|query)/i,
    description:
      "Using unvalidated input as ObjectId can cause errors or unexpected behavior",
    severity: "medium",
    suggestion:
      "Validate that the input is a valid ObjectId format before creating a new ObjectId.",
    example: "db.users.findOne({ _id: new ObjectId(req.params.id) });",
    safeExample:
      "if (ObjectId.isValid(req.params.id)) {\n  db.users.findOne({ _id: new ObjectId(req.params.id) });\n}",
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/method/ObjectId/#security",
  },
  {
    id: "PROJECTION_INJECTION",
    name: "Projection Injection",
    pattern: /\.(find|findOne)\s*\(\s*.*?\s*,\s*req\.(body|params|query)/i,
    description:
      "Using user input directly in the projection parameter can lead to information disclosure",
    severity: "high",
    suggestion:
      "Validate and sanitize projection fields. Only allow a whitelist of permitted fields.",
    example: "db.users.find({}, req.query.fields);",
    safeExample:
      'const allowedFields = ["name", "email", "createdAt"];\nconst projection = {};\nfor (const field of allowedFields) {\n  if (req.query.fields.includes(field)) projection[field] = 1;\n}\ndb.users.find({}, projection);',
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/operator/projection/positional/#security",
  },
  {
    id: "UNCONTROLLED_LIMIT",
    name: "Uncontrolled Query Limit",
    pattern: /\.limit\s*\(\s*req\.(body|params|query)/i,
    description:
      "Using unvalidated user input for limit can lead to denial of service",
    severity: "medium",
    suggestion:
      "Apply reasonable upper and lower bounds to limit values from user input.",
    example: "db.users.find({}).limit(req.query.limit);",
    safeExample:
      "const limit = Math.min(Math.max(parseInt(req.query.limit) || 10, 1), 100);\ndb.users.find({}).limit(limit);",
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/method/db.collection.find/#security",
  },
  {
    id: "SORT_INJECTION",
    name: "Sort Injection",
    pattern: /\.sort\s*\(\s*req\.(body|params|query)/i,
    description:
      "Using unvalidated sort parameters can lead to performance issues or DoS",
    severity: "medium",
    suggestion:
      "Validate sort fields and directions. Only allow sorting on indexed fields.",
    example: "db.users.find({}).sort(req.query.sort);",
    safeExample:
      'const allowedSortFields = ["name", "createdAt"];\nconst sortField = allowedSortFields.includes(req.query.sortField) ? req.query.sortField : "createdAt";\nconst sortDir = req.query.sortDir === "desc" ? -1 : 1;\ndb.users.find({}).sort({ [sortField]: sortDir });',
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/method/db.collection.find/#security",
  },
  {
    id: "OBJECT_SPREAD_INJECTION",
    name: "Object Spread Injection",
    pattern:
      /\.(find|findOne|aggregate|update|delete)\s*\(\s*\{\s*.*?,?\s*\.\.\.(\w+).*?\}/i,
    description:
      "Spreading objects directly into MongoDB queries can lead to query injection if the spread object is untrusted",
    severity: "high",
    suggestion:
      "Explicitly select only the required fields from the object instead of spreading the entire object into the query",
    example: "db.collection.find({ field: value, ...userProvidedObject });",
    safeExample:
      "const { safeField1, safeField2 } = userProvidedObject;\ndb.collection.find({ field: value, safeField1, safeField2 });",
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/operator/query/positional/#security",
  },
  {
    id: "DYNAMIC_OPERATOR_ASSIGNMENT",
    name: "Dynamic Operator Assignment",
    pattern: /\w+\s*=\s*\{\s*\$\w+:/i,
    description:
      "Dynamically assigning MongoDB operators like $in, $gte, $lte to query fields can lead to operator injection attacks",
    severity: "medium",
    suggestion:
      "Validate both the operators and values before assigning them to query properties",
    example:
      "query.field = { $in: userProvidedArray }; // Or query._id = { $gte: someValue };",
    safeExample:
      "if (Array.isArray(allowedValues) && allowedValues.every(v => typeof v === 'string')) {\n  query.field = { $in: allowedValues };\n}",
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/operator/query/positional/#security",
  },
  {
    id: "MONGOOSE_QUERY_EXEC_MISSING",
    name: "Mongoose Query Exec Missing",
    pattern:
      /\.(find|findOne|findById|update|delete|count)(?!\s*\(\s*\)|\s*\(\s*.*?\s*\)\s*\.(exec|then|catch)\b)/i,
    description:
      "Not calling .exec() or not using a callback/Promise with Mongoose queries can lead to unexpected behavior",
    severity: "low",
    suggestion:
      "Always use .exec() or a callback/Promise with Mongoose queries to ensure proper error handling",
    example: "const users = User.find({ active: true });",
    safeExample: "const users = await User.find({ active: true }).exec();",
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/method/db.collection.find/#security",
  },
  {
    id: "UNHANDLED_PROMISE_REJECTION",
    name: "Unhandled Promise Rejection",
    pattern:
      /await\s+(\w+\.)*(find|findOne|findById|update|delete|aggregate|count).*?(?!\s*try\s*\{)/i,
    description:
      "MongoDB operations without proper try/catch blocks can lead to unhandled promise rejections",
    severity: "medium",
    suggestion:
      "Always wrap MongoDB operations in try/catch blocks to handle errors properly",
    example: "const users = await db.collection('users').find().toArray();",
    safeExample:
      "try {\n  const users = await db.collection('users').find().toArray();\n} catch (error) {\n  // Handle error\n}",
    docUrl:
      "https://www.mongodb.com/docs/manual/core/transactions-in-applications/#error-handling",
  },
  {
    id: "UNESCAPED_REGEX_INPUT",
    name: "Unescaped Regex Input",
    pattern: /\{\s*['"a-zA-Z0-9_]+\s*:\s*\{\s*\$regex\s*:\s*(\w+)(?!\()/i,
    description:
      "Using unescaped user input in $regex queries can lead to regex injection attacks",
    severity: "high",
    suggestion:
      "Escape special regex characters in user input before using in $regex queries",
    example: "db.users.find({ username: { $regex: userInput } });",
    safeExample:
      "const escapedInput = userInput.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&');\ndb.users.find({ username: { $regex: escapedInput } });",
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/operator/query/regex/#security",
  },
  {
    id: "SENSITIVE_FIELD_EXPOSURE",
    name: "Sensitive Field Exposure",
    pattern:
      /\.\s*find.*\{\s*\}\s*(?!.*\{\s*password\s*:\s*0|\s*passwordHash\s*:\s*0)/i,
    description:
      "Querying without explicitly excluding sensitive fields can expose passwords and other confidential data",
    severity: "high",
    suggestion:
      "Always exclude sensitive fields like passwords or use explicit projection to include only necessary fields",
    example: "db.users.find();",
    safeExample:
      "db.users.find({}, { password: 0, passwordHash: 0 });\n// Or better: db.users.find({}, { username: 1, email: 1 });",
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/method/db.collection.find/#security",
  },
  {
    id: "UNCONTROLLED_SKIP",
    name: "Uncontrolled Skip Value",
    pattern: /\.skip\s*\(\s*req\.(body|params|query)/i,
    description:
      "Using unvalidated user input for skip can lead to performance issues or DoS",
    severity: "medium",
    suggestion:
      "Apply reasonable upper and lower bounds to skip values from user input",
    example: "db.users.find().skip(req.query.skip);",
    safeExample:
      "const skip = Math.min(Math.max(parseInt(req.query.skip) || 0, 0), 1000);\ndb.users.find().skip(skip);",
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/method/db.collection.find/#security",
  },
  {
    id: "SECRETS_IN_QUERY",
    name: "Secrets in Query",
    pattern:
      /(api[_-]?key|secret|password|token|auth[_-]?token|credential)[^\n]{1,30}(=|:)[^\n]{1,30}/i,
    description:
      "Hardcoded secrets or credentials in database queries can lead to security breaches",
    severity: "high",
    suggestion:
      "Never hardcode secrets in queries. Use environment variables or secure secret management",
    example: "db.users.find({ apiKey: 'sk_live_123456789abcdef' });",
    safeExample: "db.users.find({ apiKey: process.env.API_KEY });",
    docUrl:
      "https://www.mongodb.com/docs/manual/core/security-input-validation/",
  },
  {
    id: "DANGEROUS_PROJECTION",
    name: "Dangerous Projection Operators",
    pattern: /\$\s*:\s*(\{|\[|\$)/i,
    description:
      "Using the $ projection operator with untrusted input can lead to data exposure",
    severity: "high",
    suggestion: "Avoid using the $ operator in projections with user input",
    example: "db.users.find({}, { $: userInput });",
    safeExample: "// Use explicit field projections instead",
    docUrl:
      "https://www.mongodb.com/docs/manual/reference/operator/projection/positional/#security",
  },
  {
    id: "UNVALIDATED_UPDATE_OPERATORS",
    name: "Unvalidated Update Operators",
    pattern:
      /\.\s*(update|updateOne|updateMany|findOneAndUpdate)\s*\(\s*.*?,\s*\{\s*\$\w+\s*:/i,
    description:
      "Using update operators like $set, $unset, $inc without validation can allow field manipulation attacks",
    severity: "high",
    suggestion:
      "Validate update operators and fields before executing update operations",
    example: "db.users.updateOne({ _id }, req.body);",
    safeExample:
      "const allowedFields = ['name', 'email'];\nconst update = {};\nfor (const [key, value] of Object.entries(req.body)) {\n  if (allowedFields.includes(key)) update[key] = value;\n}\ndb.users.updateOne({ _id }, { $set: update });",
    docUrl:
      "https://www.mongodb.com/docs/manual/core/security-input-validation/",
  },
];
