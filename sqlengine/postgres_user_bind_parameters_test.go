package sqlengine_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/alphagov/paas-rds-broker/sqlengine"
)

var _ = Describe("PostgresUserBindParameters", func() {
	It("generates a correct default privilege statement for default-revoke policy", func() {
		bp := PostgresUserBindParameters {
			IsOwner: boolPointer(false),
			DefaultPrivilegePolicy: "REVOKE",
		}

		Expect(bp.Validate()).ToNot(HaveOccurred())

		defaultStatement, defaultParams := bp.GetDefaultPrivilegeStatement("someuser", "somedb")

		Expect(defaultParams).To(BeEquivalentTo([]interface{}{"someuser", "somedb"}))
		Expect(defaultStatement).To(Equal(`
	DO
	$body$
	DECLARE
		username text := quote_ident(?);
		dbname text := quote_ident(?);
	BEGIN
		FOR schema_name IN SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('pg_catalog','information_schema') LOOP
			EXECUTE 'GRANT ALL ON ALL FUNCTIONS IN SCHEMA ' || quote_ident(schema_name) || ' TO ' || username;
		END LOOP;

		FOR type_schema, type_name IN SELECT user_defined_type_schema, user_defined_type_name FROM information_schema.user_defined_types LOOP
			EXECUTE 'GRANT ALL ON TYPE ' || quote_ident(type_schema) || '.' || quote_ident(type_name) || ' TO ' || username;
		END LOOP;

		FOR domain_schema, domain_name IN SELECT domain_schema, domain_name FROM information_schema.domains LOOP
			EXECUTE 'GRANT ALL ON DOMAIN ' || quote_ident(domain_schema) || '.' || quote_ident(domain_name) || ' TO ' || username;
		END LOOP;

		FOR lang_name IN SELECT lanname FROM pg_catalog.pg_language WHERE lanpltrusted LOOP
			EXECUTE 'GRANT ALL ON LANGUAGE ' || quote_ident(lang_name) || ' TO ' || username;
		END LOOP;

		EXECUTE 'ALTER DEFAULT PRIVILEGES GRANT ALL ON FUNCTIONS TO ' || username;
		EXECUTE 'ALTER DEFAULT PRIVILEGES GRANT ALL ON TYPES TO ' || username;
	END
	$body$`))
	})

	It("generates a correct default privilege statement for default-grant policy", func() {
		bp := PostgresUserBindParameters {
			IsOwner: boolPointer(false),
			DefaultPrivilegePolicy: "GRANT",
		}

		Expect(bp.Validate()).ToNot(HaveOccurred())

		defaultStatement, defaultParams := bp.GetDefaultPrivilegeStatement("someuser", "somedb")

		Expect(defaultParams).To(BeEquivalentTo([]interface{}{"someuser", "somedb"}))
		Expect(defaultStatement).To(Equal(`
	DO
	$body$
	DECLARE
		username text := quote_ident(?);
		dbname text := quote_ident(?);
	BEGIN
		FOR schema_name IN SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('pg_catalog','information_schema') LOOP
			EXECUTE 'GRANT ALL ON ALL TABLES IN SCHEMA ' || quote_ident(schema_name) || ' TO ' || username;
			EXECUTE 'GRANT ALL ON ALL SEQUENCES IN SCHEMA ' || quote_ident(schema_name) || ' TO ' || username;
			EXECUTE 'GRANT ALL ON ALL FUNCTIONS IN SCHEMA ' || quote_ident(schema_name) || ' TO ' || username;
			EXECUTE 'GRANT ALL ON SCHEMA ' || quote_ident(schema_name) || ' TO ' || username;
		END LOOP;

		EXECUTE 'GRANT ALL ON DATABASE ' || dbname || ' TO ' || username;

		EXECUTE 'ALTER DEFAULT PRIVILEGES GRANT ALL ON TABLES TO ' || username;
		EXECUTE 'ALTER DEFAULT PRIVILEGES GRANT ALL ON SEQUENCES TO ' || username;
		EXECUTE 'ALTER DEFAULT PRIVILEGES GRANT ALL ON FUNCTIONS TO ' || username;
		EXECUTE 'ALTER DEFAULT PRIVILEGES GRANT ALL ON SCHEMAS TO ' || username;

		FOR schema_name IN SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('pg_catalog','information_schema') LOOP
			EXECUTE 'GRANT ALL ON ALL FUNCTIONS IN SCHEMA ' || quote_ident(schema_name) || ' TO ' || username;
		END LOOP;

		FOR type_schema, type_name IN SELECT user_defined_type_schema, user_defined_type_name FROM information_schema.user_defined_types LOOP
			EXECUTE 'GRANT ALL ON TYPE ' || quote_ident(type_schema) || '.' || quote_ident(type_name) || ' TO ' || username;
		END LOOP;

		FOR domain_schema, domain_name IN SELECT domain_schema, domain_name FROM information_schema.domains LOOP
			EXECUTE 'GRANT ALL ON DOMAIN ' || quote_ident(domain_schema) || '.' || quote_ident(domain_name) || ' TO ' || username;
		END LOOP;

		FOR lang_name IN SELECT lanname FROM pg_catalog.pg_language WHERE lanpltrusted LOOP
			EXECUTE 'GRANT ALL ON LANGUAGE ' || quote_ident(lang_name) || ' TO ' || username;
		END LOOP;

		EXECUTE 'ALTER DEFAULT PRIVILEGES GRANT ALL ON FUNCTIONS TO ' || username;
		EXECUTE 'ALTER DEFAULT PRIVILEGES GRANT ALL ON TYPES TO ' || username;
	END
	$body$`))
	})

	It("Generates a correct privilege assignment statement for column-targeted policies", func() {
		bp := PostgresUserBindParameters {
			IsOwner: boolPointer(false),
			DefaultPrivilegePolicy: "REVOKE",
			GrantPrivileges: &[]PostgresqlPrivilege{
				PostgresqlPrivilege{
					TargetType: "table",
					TargetName: stringPointer("Some Name"),
					TargetSchema: stringPointer("a-schema"),
					Privilege: "SELECT",
					ColumnNames: &[]string{
						"foo",
						"bar",
					},
				},
			},
		}

		Expect(bp.Validate()).ToNot(HaveOccurred())

		assnStatement, assnParams := bp.GetPrivilegeAssignmentStatement("someuser", "somedb")

		Expect(assnParams).To(BeEquivalentTo([]interface{}{"someuser", "somedb", "foo", "bar", "a-schema", "Some Name"}))
		Expect(assnStatement).To(Equal(`
	DO
	$body$
	DECLARE
		username text := quote_ident(?);
		dbname text := quote_ident(?);
	BEGIN
		BEGIN
			EXECUTE 'GRANT SELECT (' || quote_ident(?) || ', ' || quote_ident(?) || ') ON table ' || quote_ident(?) || '.' || quote_ident(?) || ' TO ' || username;
		EXCEPTION
			WHEN undefined_column OR undefined_table OR invalid_schema_name THEN
				NULL;
		END;
	END
	$body$`))
	})
})
