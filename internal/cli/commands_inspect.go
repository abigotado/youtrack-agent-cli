package cli

import (
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/spf13/cobra"
)

func (a *App) newInspectCommand() *cobra.Command {
	command := commandGroup("inspect", "Perform exact or bounded REST reads for write preparation")
	command.AddCommand(a.newInspectIssueCommand(), a.newInspectProjectCommand(), a.newInspectSchemaCommand())
	return command
}

func (a *App) newInspectIssueCommand() *cobra.Command {
	var id string
	command := &cobra.Command{
		Use: "issue", Short: "Read one exact issue through the narrow REST helper", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.requireProfile(); err != nil {
				return err
			}
			if id == "" {
				return errx.Usage("inspect issue requires --id")
			}
			value, selected, err := a.service.InspectIssueInfo(cmd.Context(), a.profileName, id)
			if err != nil {
				return err
			}
			a.out.WithContext(selected.Name, selected.Instance, selected.AccountID, selected.Login)
			return a.out.Success(newIssueView(value))
		},
	}
	command.Flags().StringVar(&id, "id", "", "exact YouTrack issue database ID or readable ID")
	return command
}

func (a *App) newInspectProjectCommand() *cobra.Command {
	var id string
	command := &cobra.Command{
		Use: "project", Short: "Read one exact project", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.requireProfile(); err != nil {
				return err
			}
			if id == "" {
				return errx.Usage("inspect project requires --project")
			}
			value, selected, err := a.service.InspectProjectInfo(cmd.Context(), a.profileName, id)
			if err != nil {
				return err
			}
			a.out.WithContext(selected.Name, selected.Instance, selected.AccountID, selected.Login)
			return a.out.Success(newProjectView(value))
		},
	}
	command.Flags().StringVar(&id, "project", "", "exact project entity ID or key")
	return command
}

func (a *App) newInspectSchemaCommand() *cobra.Command {
	var id string
	var limit int
	var offset int
	command := &cobra.Command{
		Use: "schema", Short: "Read one bounded page of project field schema", Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.requireProfile(); err != nil {
				return err
			}
			if id == "" {
				return errx.Usage("inspect schema requires --project")
			}
			if limit < 1 || limit > 100 || offset < 0 {
				return errx.Usage("--limit must be 1-100 and --offset must be nonnegative")
			}
			value, truncated, selected, err := a.service.InspectSchemaInfo(cmd.Context(), a.profileName, id, limit, offset)
			if err != nil {
				return err
			}
			a.out.WithContext(selected.Name, selected.Instance, selected.AccountID, selected.Login)
			views := make([]projectFieldView, len(value))
			for index, field := range value {
				views[index] = newProjectFieldView(field)
			}
			return a.out.SuccessPage(views, truncated, "")
		},
	}
	flags := command.Flags()
	flags.StringVar(&id, "project", "", "exact project entity ID or key")
	flags.IntVar(&limit, "limit", 50, "maximum field schemas in this page (1-100)")
	flags.IntVar(&offset, "offset", 0, "explicit bounded page offset")
	return command
}
