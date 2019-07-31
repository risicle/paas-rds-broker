package rdsbroker

import "fmt"
import "strings"
import "unicode"

type ProvisionParameters struct {
	BackupRetentionPeriod       int64    `json:"backup_retention_period"`
	CharacterSetName            string   `json:"character_set_name"`
	DBName                      string   `json:"dbname"`
	PreferredBackupWindow       string   `json:"preferred_backup_window"`
	PreferredMaintenanceWindow  string   `json:"preferred_maintenance_window"`
	SkipFinalSnapshot           *bool    `json:"skip_final_snapshot"`
	RestoreFromLatestSnapshotOf *string  `json:"restore_from_latest_snapshot_of"`
	Extensions                  []string `json:"enable_extensions"`
}

type UpdateParameters struct {
	ApplyAtMaintenanceWindow   bool     `json:"apply_at_maintenance_window"`
	BackupRetentionPeriod      int64    `json:"backup_retention_period"`
	PreferredBackupWindow      string   `json:"preferred_backup_window"`
	PreferredMaintenanceWindow string   `json:"preferred_maintenance_window"`
	SkipFinalSnapshot          *bool    `json:"skip_final_snapshot"`
	Reboot                     *bool    `json:"reboot"`
	ForceFailover              *bool    `json:"force_failover"`
	EnableExtensions           []string `json:"enable_extensions"`
	DisableExtensions          []string `json:"disable_extensions"`
}

type PostgresqlPrivilege struct {
	TargetType   string    `json:"target_type"`
	TargetSchema *string   `json:"target_schema"`
	TargetName   *string   `json:"target_name"`
	Privilege    string    `json:"privilege"`
	ColumnNames  *[]string `json:"column_names"`
}

type BindParameters struct {
	PostgresqlUser *struct {
		IsOwner                *bool                  `json:"is_owner"`
		DefaultPrivilegePolicy string                 `json:"default_privilege_policy"`
		RevokePrivileges       *[]PostgresqlPrivilege `json:"revoke_privileges"`
		GrantPrivileges        *[]PostgresqlPrivilege `json:"grant_privileges"`
	}                                                 `json:"postgresql_user"`
}

func ValidatePostgresqlName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("Empty name")
	}

	for i := 0; i < len(name); i++ {
		if name[i] > unicode.MaxASCII {
			return fmt.Errorf("Non-ASCII characters in postgresql object names not (yet) supported: %s", name)
		}
		if name[i] == '"' {
			return fmt.Errorf("Double-quotes in postgresql object names not allowed: %s", name)
		}
    }

    return nil
}

func (pp *ProvisionParameters) Validate() error {
	return nil
}

func (up *UpdateParameters) Validate() error {
	for _, ext1 := range up.EnableExtensions {
		for _, ext2 := range up.DisableExtensions {
			if ext1 == ext2 {
				return fmt.Errorf("%s is set in both enable_extensions and disable_extensions", ext1)
			}
		}
	}
	return nil
}

func (bp *BindParameters) Validate() error {
	if bp.PostgresqlUser != nil {
		if bp.PostgresqlUser.IsOwner != nil && !*bp.PostgresqlUser.IsOwner {
			switch bp.PostgresqlUser.DefaultPrivilegePolicy {
				case "revoke":
					if bp.PostgresqlUser.RevokePrivileges != nil {
						return fmt.Errorf("revoke_privileges makes no sense with default_privilege_policy 'revoke' (%+v)", *bp)
					}
					if bp.PostgresqlUser.GrantPrivileges != nil {
						for _, privilege := range *bp.PostgresqlUser.GrantPrivileges {
							if err := privilege.Validate(); err != nil {
								return err
							}
						}
					}
				case "grant":
					if bp.PostgresqlUser.GrantPrivileges != nil {
						return fmt.Errorf("grant_privileges makes no sense with default_privilege_policy 'grant' (%+v)", *bp)
					}
					if bp.PostgresqlUser.RevokePrivileges != nil {
						for _, privilege := range *bp.PostgresqlUser.RevokePrivileges {
							if err := privilege.Validate(); err != nil {
								return err
							}
						}
					}
				default:
					return fmt.Errorf("default_privilege_policy must be one of 'grant' or 'revoke' (%+v)", *bp)
			}
		} else {
			if bp.PostgresqlUser.DefaultPrivilegePolicy != "" {
				return fmt.Errorf("postgresql_user.default_privilege_policy makes no sense for owner (%+v)", *bp)
			}
			if bp.PostgresqlUser.RevokePrivileges != nil {
				return fmt.Errorf("postgresql_user.revoke_privileges makes no sense for owner (%+v)", *bp)
			}
			if bp.PostgresqlUser.GrantPrivileges != nil {
				return fmt.Errorf("postgresql_user.grant_privileges makes no sense for owner (%+v)", *bp)
			}
		}
	}
	return nil
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
