package sqlengine

import (
	"fmt"
	"strings"
	"unicode"
)

type PostgresqlPrivilege struct {
	TargetType   string    `json:"target_type"`
	TargetSchema *string   `json:"target_schema"`
	TargetName   *string   `json:"target_name"`
	Privilege    string    `json:"privilege"`
	ColumnNames  *[]string `json:"column_names"`
}

func (pp *PostgresqlPrivilege) Validate() error {
	switch strings.ToUpper(pp.TargetType) {
		case "TABLE":
			if pp.TargetName == nil || *pp.TargetName == "" {
				return fmt.Errorf("Must provide a non-empty target_name for 'TABLE' postgresql privilege target_type (%+v)", *pp)
			}

			if err := ValidatePostgresqlName(*pp.TargetName); err != nil {
				return err
			}

			if pp.TargetSchema != nil && *pp.TargetSchema != "" {
				if err := ValidatePostgresqlName(*pp.TargetSchema); err != nil {
					return err
				}
			}

			if pp.ColumnNames != nil && len(*pp.ColumnNames) != 0 {
				for _, columnName := range *pp.ColumnNames {
					if err := ValidatePostgresqlName(columnName); err != nil {
						return err
					}
				}

				switch strings.ToUpper(pp.Privilege) {
					case "SELECT":
					case "INSERT":
					case "UPDATE":
					case "REFERENCES":
					case "ALL":
					default:
						return fmt.Errorf("Unknown postgresql column privilege: %s", pp.Privilege)
				}
			} else {
				switch strings.ToUpper(pp.Privilege) {
					case "SELECT":
					case "INSERT":
					case "UPDATE":
					case "DELETE":
					case "TRUNCATE":
					case "REFERENCES":
					case "TRIGGER":
					case "ALL":
					default:
						return fmt.Errorf("Unknown postgresql table privilege: %s", pp.Privilege)
				}
			}
		case "SEQUENCE":
			if pp.TargetName == nil || *pp.TargetName == "" {
				return fmt.Errorf("Must provide a non-empty target_name for 'SEQUENCE' postgresql privilege target_type (%+v)", *pp)
			}

			if err := ValidatePostgresqlName(*pp.TargetName); err != nil {
				return err
			}

			if pp.TargetSchema != nil && *pp.TargetSchema != "" {
				if err := ValidatePostgresqlName(*pp.TargetSchema); err != nil {
					return err
				}
			}

			if pp.ColumnNames != nil {
				return fmt.Errorf("column_names makes no sense for 'SEQUENCE' postgresql privilege target_type (%+v)", *pp)
			}

			switch strings.ToUpper(pp.Privilege) {
				case "USAGE":
				case "SELECT":
				case "UPDATE":
				case "ALL":
				default:
					return fmt.Errorf("Unknown postgresql sequence privilege: %s", pp.Privilege)
			}
		case "DATABASE":
			if pp.TargetName != nil {
				return fmt.Errorf("target_name makes no sense for 'DATABASE' postgresql privilege target_type (%+v)", *pp)
			}

			if pp.TargetSchema != nil {
				return fmt.Errorf("target_schema makes no sense for 'DATABASE' postgresql privilege target_type (%+v)", *pp)
			}

			if pp.ColumnNames != nil {
				return fmt.Errorf("column_names makes no sense for 'DATABASE' postgresql privilege target_type (%+v)", *pp)
			}

			switch strings.ToUpper(pp.Privilege) {
				case "CREATE":
				case "TEMPORARY":
				case "TEMP":
				case "ALL":
				default:
					return fmt.Errorf("Unknown postgresql database privilege: %s", pp.Privilege)
			}
		case "SCHEMA":
			if pp.TargetName == nil || *pp.TargetName == "" {
				return fmt.Errorf("Must provide a non-empty target_name for 'SCHEMA' postgresql privilege target_type (%+v)", *pp)
			}

			if err := ValidatePostgresqlName(*pp.TargetName); err != nil {
				return err
			}

			if pp.TargetSchema != nil {
				return fmt.Errorf("target_schema makes no sense for 'SCHEMA' postgresql privilege target_type (try target_name instead) (%+v)", *pp)
			}

			if pp.ColumnNames != nil {
				return fmt.Errorf("column_names makes no sense for 'SCHEMA' postgresql privilege target_type (%+v)", *pp)
			}

			switch strings.ToUpper(pp.Privilege) {
				case "CREATE":
				case "USAGE":
				case "ALL":
				default:
					return fmt.Errorf("Unknown postgresql schema privilege: %s", pp.Privilege)
			}
		default:
			return fmt.Errorf("Unknown postgresql privilege target_type: %s", pp.TargetType)
	}

	return nil
}

func getQuotedIdents(schema *string, name string) (text string, parameters []interface{}) {
	if schema == nil || *schema == "" {
		return "quote_ident(?)", []interface{}{name}
	}

	return "quote_ident(?) || '.' || quote_ident(?)", []interface{}{*schema, name}
}

const privilegeStatementWrapper = `BEGIN
			%s
		EXCEPTION
			WHEN undefined_column OR undefined_table OR invalid_schema_name THEN
				NULL;
		END;`

func (pp *PostgresqlPrivilege) getPlPgSQL(action string) (text string, parameters []interface{}) {
	if strings.ToUpper(pp.TargetType) == "TABLE" && pp.ColumnNames != nil && len(*pp.ColumnNames) != 0 {
		columnQuoteIdents := make([]string, len(*pp.ColumnNames))
		for i := range columnQuoteIdents {
			columnQuoteIdents[i] = "quote_ident(?)"
		}

		tableQuotedIdents, tableQuotedIdentsParameters := getQuotedIdents(pp.TargetSchema, *pp.TargetName)
		parameters := make([]interface{}, len(*pp.ColumnNames))
		for i, col := range *pp.ColumnNames {
			parameters[i] = col
		}

		return fmt.Sprintf(
			privilegeStatementWrapper,
			fmt.Sprintf(
				"EXECUTE '%s %s (' || %s || ') ON %s ' || %s || ' TO ' || username;",
				action,
				pp.Privilege,
				strings.Join(columnQuoteIdents, " || ', ' || "),
				pp.TargetType,
				tableQuotedIdents,
			),
		), append(
			parameters,
			tableQuotedIdentsParameters...
		)
	}
	if strings.ToUpper(pp.TargetType) == "DATABASE" {
		return fmt.Sprintf(
			privilegeStatementWrapper,
			fmt.Sprintf(
				"EXECUTE '%s %s ON %s ' || dbname || ' TO ' || username;",
				action,
				pp.Privilege,
				pp.TargetType,
			),
		), []interface{}{}
	}
	if strings.ToUpper(pp.TargetType) == "SCHEMA" {
		return fmt.Sprintf(
			privilegeStatementWrapper,
			fmt.Sprintf(
				"EXECUTE '%s %s ON %s ' || quote_ident(?) || ' TO ' || username;",
				action,
				pp.Privilege,
				pp.TargetType,
			),
		), []interface{}{
			*pp.TargetName,
		}
	}

	targetQuotedIdents, targetQuotedIdentsParameters := getQuotedIdents(pp.TargetSchema, *pp.TargetName)

	return fmt.Sprintf(
		privilegeStatementWrapper,
		fmt.Sprintf(
			"EXECUTE '%s %s ON %s ' || %s || ' TO ' || username;",
			action,
			pp.Privilege,
			pp.TargetType,
			targetQuotedIdents,
		),
	), append(
		targetQuotedIdentsParameters,
	)
}

func ValidatePostgresqlName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("Empty name")
	}

	for i := 0; i < len(name); i++ {
		if name[i] > unicode.MaxASCII {
			return fmt.Errorf("Non-ASCII characters in postgresql object names not (yet) supported: %s", name)
		}
	}

	return nil
}

type PostgresUserBindParameters struct {
	IsOwner                *bool                  `json:"is_owner"`
	DefaultPrivilegePolicy string                 `json:"default_privilege_policy"`
	RevokePrivileges       *[]PostgresqlPrivilege `json:"revoke_privileges"`
	GrantPrivileges        *[]PostgresqlPrivilege `json:"grant_privileges"`
}

func (bp *PostgresUserBindParameters) Validate() error {
	if bp.IsOwner != nil && !*bp.IsOwner {
		switch strings.ToLower(bp.DefaultPrivilegePolicy) {
			case "revoke":
				if bp.RevokePrivileges != nil {
					return fmt.Errorf("revoke_privileges makes no sense with default_privilege_policy 'revoke' (%+v)", *bp)
				}
				if bp.GrantPrivileges != nil {
					for _, privilege := range *bp.GrantPrivileges {
						if err := privilege.Validate(); err != nil {
							return err
						}
					}
				}
			case "grant":
				if bp.GrantPrivileges != nil {
					return fmt.Errorf("grant_privileges makes no sense with default_privilege_policy 'grant' (%+v)", *bp)
				}
				if bp.RevokePrivileges != nil {
					for _, privilege := range *bp.RevokePrivileges {
						if err := privilege.Validate(); err != nil {
							return err
						}
					}
				}
			default:
				return fmt.Errorf("default_privilege_policy must be one of 'grant' or 'revoke' (%+v)", *bp)
		}
	} else {
		if bp.DefaultPrivilegePolicy != "" {
			return fmt.Errorf("postgresql_user.default_privilege_policy makes no sense for owner (%+v)", *bp)
		}
		if bp.RevokePrivileges != nil {
			return fmt.Errorf("postgresql_user.revoke_privileges makes no sense for owner (%+v)", *bp)
		}
		if bp.GrantPrivileges != nil {
			return fmt.Errorf("postgresql_user.grant_privileges makes no sense for owner (%+v)", *bp)
		}
	}
	return nil
}

const grantAllPrivilegesFragment = `FOR schema_name IN SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('pg_catalog','information_schema') LOOP
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

		`

const grantUnhandledPrivilegesFragment = `FOR schema_name IN SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('pg_catalog','information_schema') LOOP
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
		EXECUTE 'ALTER DEFAULT PRIVILEGES GRANT ALL ON TYPES TO ' || username;`

const immediatePlPgSQLWrapper = `
	DO
	$body$
	DECLARE
		username text := quote_ident(?);
		dbname text := quote_ident(?);
	BEGIN
		%s
	END
	$body$`

func (bp *PostgresUserBindParameters) GetDefaultPrivilegeStatement(username string, dbname string) (statement string, parameters []interface{}) {
	var statementBuilder strings.Builder

	if strings.ToLower(bp.DefaultPrivilegePolicy) != "revoke" {
		// grant priviliges to all objects which can then be revoked individually
		statementBuilder.WriteString(grantAllPrivilegesFragment)
	}

	// we don't implement a way to further control some types of privilege, so for these features to be at all
	// usable by a non-owner user, we need to allow all of them
	statementBuilder.WriteString(grantUnhandledPrivilegesFragment)

	return fmt.Sprintf(immediatePlPgSQLWrapper, statementBuilder.String()), []interface{}{username, dbname}
}

func (bp *PostgresUserBindParameters) GetPrivilegeAssignmentStatement(username string, dbname string) (statement string, parameters []interface{}) {
	var privs *[]PostgresqlPrivilege
	var privsAction string
	if strings.ToLower(bp.DefaultPrivilegePolicy) != "revoke" {
		privs = bp.RevokePrivileges
		privsAction = "REVOKE"
	} else {
		privs = bp.GrantPrivileges
		privsAction = "GRANT"
	}

	if privs == nil || len(*privs) == 0 || bp.IsOwner == nil || *bp.IsOwner {
		return "", []interface{}{}
	}

	var privsBuilder strings.Builder
	var privsParameters []interface{}
	for _, priv := range *privs {
		privPlPgSQL, privParameters := priv.getPlPgSQL(privsAction)

		privsBuilder.WriteString(privPlPgSQL)
		privsParameters = append(privsParameters, privParameters...)
	}

	wrapperParameters := []interface{}{
		username,
		dbname,
	}

	return fmt.Sprintf(immediatePlPgSQLWrapper, privsBuilder.String()), append(wrapperParameters, privsParameters...)
}
