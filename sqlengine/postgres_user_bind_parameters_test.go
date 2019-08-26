package sqlengine

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("PostgresUserBindParameters", func() {
	var _ = Describe("Validation", func() {
		It("returns an error for extra options used with a non-owner postgresql user", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(true),
				GrantPrivileges: &[]PostgresqlPrivilege{},
			}

			err := bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`postgresql_user.grant_privileges makes no sense for owner`)))

			bp = PostgresUserBindParameters {
				RevokePrivileges: &[]PostgresqlPrivilege{},
			}

			err = bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`postgresql_user.revoke_privileges makes no sense for owner`)))

			bp = PostgresUserBindParameters {
				IsOwner: boolPointer(true),
				DefaultPrivilegePolicy: "grant",
			}

			err = bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`postgresql_user.default_privilege_policy makes no sense for owner`)))
		})

		It("returns an error for unexpected default_privilege_policy", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "perhaps",
			}

			err := bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`default_privilege_policy must be one of 'grant' or 'revoke'`)))
		})

		It("returns an error for a privileges list clashing with default_privilege_policy", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "grant",
				GrantPrivileges: &[]PostgresqlPrivilege{},
			}

			err := bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`grant_privileges makes no sense with default_privilege_policy 'grant'`)))

			bp = PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "revoke",
				RevokePrivileges: &[]PostgresqlPrivilege{},
			}

			err = bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`revoke_privileges makes no sense with default_privilege_policy 'revoke'`)))
		})

		It("returns an error for unknown privilege target_type", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "grant",
				RevokePrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "foo",
					},
				},
			}

			err := bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`Unknown postgresql privilege target_type: foo`)))
		})

		It("returns an error if no target_name supplied with TABLE target_type", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "grant",
				RevokePrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "table",
						Privilege: "ALL",
					},
				},
			}

			err := bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`Must provide a non-empty target_name for 'TABLE' postgresql privilege target_type`)))
		})

		It("returns an error if an invalid target_name or schema_name is supplied with TABLE target_type", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "grant",
				RevokePrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "table",
						TargetName: stringPointer("bar ✈"),
						Privilege: "ALL",
					},
				},
			}

			err := bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`Non-ASCII characters in postgresql object names not (yet) supported`)))

			bp = PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "grant",
				RevokePrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "table",
						TargetSchema: stringPointer("in✈valid"),
						TargetName: stringPointer("something;valid"),
						Privilege: "ALL",
					},
				},
			}

			err = bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`Non-ASCII characters in postgresql object names not (yet) supported`)))
		})

		It("returns an error if invalid column_names are supplied with TABLE target_type", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "revoke",
				GrantPrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "TABLE",
						TargetName: stringPointer("some_table"),
						Privilege: "select",
						ColumnNames: &[]string{
							"valid 123",
							"✈",
						},
					},
				},
			}

			err := bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`Non-ASCII characters in postgresql object names not (yet) supported: ✈`)))
		})

		It("returns an error if invalid column_names are supplied with TABLE target_type", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "revoke",
				GrantPrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "TABLE",
						TargetName: stringPointer("some_table"),
						Privilege: "delete",
						ColumnNames: &[]string{
							"valid 123",
						},
					},
				},
			}

			err := bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`Unknown postgresql column privilege: delete`)))
		})

		It("returns an error if an invalid target_name or schema_name is supplied with TABLE target_type", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "grant",
				RevokePrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "SEQUENCE",
						TargetSchema: stringPointer("invalid✈"),
						TargetName: stringPointer("bar"),
						Privilege: "ALL",
					},
				},
			}

			err := bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`Non-ASCII characters in postgresql object names not (yet) supported: invalid✈`)))

			bp = PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "grant",
				RevokePrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "SEQUENCE",
						TargetName: stringPointer("bar"),
						Privilege: "ALL",
						ColumnNames: &[]string{
							"valid 123",
						},
					},
				},
			}

			err = bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`column_names makes no sense for 'SEQUENCE' postgresql privilege target_type`)))
		})

		It("returns an error if an inappropriate privilege is specified with SEQUENCE target_type", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "revoke",
				GrantPrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "SEQUENCE",
						TargetName: stringPointer("bar"),
						Privilege: "INSERT",
					},
				},
			}

			err := bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`Unknown postgresql sequence privilege: INSERT`)))
		})

		It("returns an error if inappropriate options are specified with DATABASE target_type", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "grant",
				RevokePrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "database",
						TargetName: stringPointer("bar"),
						Privilege: "ALL",
					},
				},
			}

			err := bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`target_name makes no sense for 'DATABASE' postgresql privilege target_type`)))

			bp = PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "grant",
				RevokePrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "DATABASE",
						TargetSchema: stringPointer("foo123"),
						Privilege: "ALL",
					},
				},
			}

			err = bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`target_schema makes no sense for 'DATABASE' postgresql privilege target_type`)))

			bp = PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "revoke",
				GrantPrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "DATABASE",
						Privilege: "ALL",
						ColumnNames: &[]string{
							"valid 123",
						},
					},
				},
			}

			err = bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`column_names makes no sense for 'DATABASE' postgresql privilege target_type`)))
		})

		It("returns an error if an inappropriate privilege is specified with DATABASE target_type", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "revoke",
				GrantPrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "DATABASE",
						Privilege: "INSERT",
					},
				},
			}

			err := bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`Unknown postgresql database privilege: INSERT`)))
		})

		It("returns an error if no target_name supplied with SCHEMA target_type", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "grant",
				RevokePrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "schema",
						Privilege: "all",
					},
				},
			}

			err := bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`Must provide a non-empty target_name for 'SCHEMA' postgresql privilege target_type`)))
		})

		It("returns an error if invalid target_name supplied with SCHEMA target_type", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "grant",
				RevokePrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "schema",
						TargetName: stringPointer("invalid✈"),
						Privilege: "all",
					},
				},
			}

			err := bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`Non-ASCII characters in postgresql object names not (yet) supported: invalid✈`)))
		})

		It("returns an error if inappropriate options are specified with SCHEMA target_type", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "grant",
				RevokePrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "SCHEMA",
						TargetSchema: stringPointer("foo"),
						TargetName: stringPointer("bar"),
						Privilege: "ALL",
					},
				},
			}

			err := bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`target_schema makes no sense for 'SCHEMA' postgresql privilege target_type (try target_name instead)`)))

			bp = PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "grant",
				RevokePrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "SCHEMA",
						TargetName: stringPointer("bar"),
						Privilege: "ALL",
						ColumnNames: &[]string{
							"valid 123",
						},
					},
				},
			}

			err = bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`column_names makes no sense for 'SCHEMA' postgresql privilege target_type`)))
		})

		It("returns an error if an inappropriate privilege is specified with SCHEMA target_type", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "revoke",
				GrantPrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "schema",
						TargetName: stringPointer("bar"),
						Privilege: "EXECUTE",
					},
				},
			}

			err := bp.Validate()
			Expect(err).To(MatchError(ContainSubstring(`Unknown postgresql schema privilege: EXECUTE`)))
		})
	})

	Describe("Statement generation", func() {
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
			EXECUTE 'GRANT SELECT (' || quote_ident(?) || ', ' || quote_ident(?) || ') ON TABLE ' || quote_ident(?) || '.' || quote_ident(?) || ' TO ' || username;
		EXCEPTION
			WHEN undefined_column OR undefined_table OR invalid_schema_name THEN
				NULL;
		END;
	END
	$body$`))
		})

		It("Generates a correct privilege assignment statement for table-targeted policies", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "GRANT",
				RevokePrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "table",
						TargetName: stringPointer("Some Name"),
						Privilege: "DELETE",
						ColumnNames: &[]string{},
					},
				},
			}

			Expect(bp.Validate()).ToNot(HaveOccurred())

			assnStatement, assnParams := bp.GetPrivilegeAssignmentStatement("someuser", "somedb")

			Expect(assnParams).To(BeEquivalentTo([]interface{}{"someuser", "somedb", "Some Name"}))
			Expect(assnStatement).To(Equal(`
	DO
	$body$
	DECLARE
		username text := quote_ident(?);
		dbname text := quote_ident(?);
	BEGIN
		BEGIN
			EXECUTE 'REVOKE DELETE ON TABLE ' || quote_ident(?) || ' TO ' || username;
		EXCEPTION
			WHEN undefined_column OR undefined_table OR invalid_schema_name THEN
				NULL;
		END;
	END
	$body$`))
		})

		It("Generates a correct privilege assignment statement for database-targeted policies", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "GRANT",
				RevokePrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "DATABASE",
						Privilege: "TEMP",
					},
				},
			}

			Expect(bp.Validate()).ToNot(HaveOccurred())

			assnStatement, assnParams := bp.GetPrivilegeAssignmentStatement("someuser", "somedb")

			Expect(assnParams).To(BeEquivalentTo([]interface{}{"someuser", "somedb"}))
			Expect(assnStatement).To(Equal(`
	DO
	$body$
	DECLARE
		username text := quote_ident(?);
		dbname text := quote_ident(?);
	BEGIN
		BEGIN
			EXECUTE 'REVOKE TEMP ON DATABASE ' || dbname || ' TO ' || username;
		EXCEPTION
			WHEN undefined_column OR undefined_table OR invalid_schema_name THEN
				NULL;
		END;
	END
	$body$`))
		})

		It("Generates a correct privilege assignment statement for schema-targeted policies", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "revoke",
				GrantPrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "Schema",
						Privilege: "CREATE",
						TargetName: stringPointer("abc123"),
					},
				},
			}

			Expect(bp.Validate()).ToNot(HaveOccurred())

			assnStatement, assnParams := bp.GetPrivilegeAssignmentStatement("someuser", "somedb")

			Expect(assnParams).To(BeEquivalentTo([]interface{}{"someuser", "somedb", "abc123"}))
			Expect(assnStatement).To(Equal(`
	DO
	$body$
	DECLARE
		username text := quote_ident(?);
		dbname text := quote_ident(?);
	BEGIN
		BEGIN
			EXECUTE 'GRANT CREATE ON SCHEMA ' || quote_ident(?) || ' TO ' || username;
		EXCEPTION
			WHEN undefined_column OR undefined_table OR invalid_schema_name THEN
				NULL;
		END;
	END
	$body$`))
		})

		It("Generates a correct privilege assignment statement for sequence-targeted policies", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "revoke",
				GrantPrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "sequence",
						Privilege: "ALL",
						TargetSchema: stringPointer("Some Schema"),
						TargetName: stringPointer("abc123"),
					},
				},
			}

			Expect(bp.Validate()).ToNot(HaveOccurred())

			assnStatement, assnParams := bp.GetPrivilegeAssignmentStatement("someuser", "somedb")

			Expect(assnParams).To(BeEquivalentTo([]interface{}{"someuser", "somedb", "Some Schema", "abc123"}))
			Expect(assnStatement).To(Equal(`
	DO
	$body$
	DECLARE
		username text := quote_ident(?);
		dbname text := quote_ident(?);
	BEGIN
		BEGIN
			EXECUTE 'GRANT ALL ON SEQUENCE ' || quote_ident(?) || '.' || quote_ident(?) || ' TO ' || username;
		EXCEPTION
			WHEN undefined_column OR undefined_table OR invalid_schema_name THEN
				NULL;
		END;
	END
	$body$`))
		})

		It("Generates a correct privilege assignment statement for multi-clause policies", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "grant",
				RevokePrivileges: &[]PostgresqlPrivilege{
					PostgresqlPrivilege{
						TargetType: "table",
						TargetName: stringPointer("Some Name"),
						TargetSchema: stringPointer("a-schema"),
						Privilege: "UPDATE",
						ColumnNames: &[]string{
							"foo",
							"bar",
							"b a z",
						},
					},
					PostgresqlPrivilege{
						TargetType: "database",
						Privilege: "all",
					},
					PostgresqlPrivilege{
						TargetType: "TABLE",
						TargetName: stringPointer("Some Name"),
						TargetSchema: stringPointer("a-schema"),
						Privilege: "SELECT",
						ColumnNames: &[]string{
							"qux",
						},
					},
					PostgresqlPrivilege{
						TargetType: "sequence",
						Privilege: "USAGE",
						TargetName: stringPointer("abc123"),
					},
				},
			}

			Expect(bp.Validate()).ToNot(HaveOccurred())

			assnStatement, assnParams := bp.GetPrivilegeAssignmentStatement("someuser", "somedb")

			Expect(assnParams).To(BeEquivalentTo([]interface{}{"someuser", "somedb", "foo", "bar", "b a z", "a-schema", "Some Name", "qux", "a-schema", "Some Name", "abc123"}))
			Expect(assnStatement).To(Equal(`
	DO
	$body$
	DECLARE
		username text := quote_ident(?);
		dbname text := quote_ident(?);
	BEGIN
		BEGIN
			EXECUTE 'REVOKE UPDATE (' || quote_ident(?) || ', ' || quote_ident(?) || ', ' || quote_ident(?) || ') ON TABLE ' || quote_ident(?) || '.' || quote_ident(?) || ' TO ' || username;
		EXCEPTION
			WHEN undefined_column OR undefined_table OR invalid_schema_name THEN
				NULL;
		END;
		BEGIN
			EXECUTE 'REVOKE ALL ON DATABASE ' || dbname || ' TO ' || username;
		EXCEPTION
			WHEN undefined_column OR undefined_table OR invalid_schema_name THEN
				NULL;
		END;
		BEGIN
			EXECUTE 'REVOKE SELECT (' || quote_ident(?) || ') ON TABLE ' || quote_ident(?) || '.' || quote_ident(?) || ' TO ' || username;
		EXCEPTION
			WHEN undefined_column OR undefined_table OR invalid_schema_name THEN
				NULL;
		END;
		BEGIN
			EXECUTE 'REVOKE USAGE ON SEQUENCE ' || quote_ident(?) || ' TO ' || username;
		EXCEPTION
			WHEN undefined_column OR undefined_table OR invalid_schema_name THEN
				NULL;
		END;
	END
	$body$`))
		})

		It("Generates an empty privilege assignment statement for privilege-less policies", func() {
			bp := PostgresUserBindParameters {
				IsOwner: boolPointer(false),
				DefaultPrivilegePolicy: "grant",
			}

			Expect(bp.Validate()).ToNot(HaveOccurred())

			assnStatement, assnParams := bp.GetPrivilegeAssignmentStatement("someuser", "somedb")

			Expect(assnParams).To(BeEquivalentTo([]interface{}{}))
			Expect(assnStatement).To(Equal(""))
		})
	})
})
