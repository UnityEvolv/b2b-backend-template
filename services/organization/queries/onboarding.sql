-- name: ListOnboardingDismissals :many
SELECT step_id FROM onboarding_dismissals WHERE org_id = @org_id;

-- name: DismissOnboarding :execrows
-- Once: a second dismissal changes nothing.
INSERT INTO onboarding_dismissals (org_id, step_id) VALUES (@org_id, @step_id)
ON CONFLICT (org_id, step_id) DO NOTHING;

-- name: RestoreOnboarding :execrows
DELETE FROM onboarding_dismissals WHERE org_id = @org_id AND step_id = @step_id;

-- name: DeleteOrgOnboardingDismissals :exec
DELETE FROM onboarding_dismissals WHERE org_id = @org_id;
