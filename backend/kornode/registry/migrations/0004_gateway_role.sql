-- D-84: the role that lets other nodes leave through an agent is `gateway`, no longer
-- `exit`. `roles` is a JSON array of role names, so the quoted name is unambiguous.
UPDATE nodes SET roles = replace(roles, '"exit"', '"gateway"') WHERE roles LIKE '%"exit"%';
