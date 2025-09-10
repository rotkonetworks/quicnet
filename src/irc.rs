// src/irc.rs
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum Command {
    // connection registration
    Pass(String),
    Nick(String),
    User(String, String, String, String),
    
    // channel operations
    Join(Vec<String>),
    Part(Vec<String>, Option<String>),
    Topic(String, Option<String>),
    Names(Vec<String>),
    List(Option<Vec<String>>),
    
    // messaging
    Privmsg(String, String),
    Notice(String, String),
    
    // server queries
    Motd,
    Who(String),
    Whois(String),
    
    // control
    Mode(String, Option<String>),
    Kick(String, String, Option<String>),
    Quit(Option<String>),
    
    // misc
    Ping(String),
    Pong(String),
    
    // raw/unknown
    Raw(String, Vec<String>),
}

impl Command {
    pub fn parse(line: &str) -> Result<Self> {
        // strip prefix if present (":source COMMAND")
        let line = if line.starts_with(':') {
            line.split_once(' ').map(|(_, rest)| rest).unwrap_or(line)
        } else {
            line
        };
        
        // find command and args
        let (cmd, args) = line.split_once(' ').unwrap_or((line, ""));
        let cmd = cmd.to_uppercase();
        
        // parse arguments
        let mut params = Vec::new();
        let mut trailing = None;
        
        if !args.is_empty() {
            if let Some((params_str, trail)) = args.split_once(" :") {
                // has trailing parameter
                params.extend(params_str.split_whitespace().map(String::from));
                trailing = Some(trail.to_string());
            } else if args.starts_with(':') {
                // only trailing parameter
                trailing = Some(args[1..].to_string());
            } else {
                // only regular parameters
                params.extend(args.split_whitespace().map(String::from));
            }
        }
        
        // match command
        Ok(match cmd.as_str() {
            "PASS" => Command::Pass(trailing.or_else(|| params.get(0).cloned()).unwrap_or_default()),
            "NICK" => Command::Nick(params.get(0).cloned().unwrap_or_default()),
            "USER" => Command::User(
                params.get(0).cloned().unwrap_or_default(),
                params.get(1).cloned().unwrap_or_default(),
                params.get(2).cloned().unwrap_or_default(),
                trailing.unwrap_or_else(|| params.get(3).cloned().unwrap_or_default()),
            ),
            "JOIN" => {
                let channels = params.get(0)
                    .map(|s| s.split(',').map(String::from).collect())
                    .unwrap_or_default();
                Command::Join(channels)
            },
            "PART" => {
                let channels = params.get(0)
                    .map(|s| s.split(',').map(String::from).collect())
                    .unwrap_or_default();
                Command::Part(channels, trailing)
            },
            "PRIVMSG" => Command::Privmsg(
                params.get(0).cloned().unwrap_or_default(),
                trailing.unwrap_or_default(),
            ),
            "NOTICE" => Command::Notice(
                params.get(0).cloned().unwrap_or_default(),
                trailing.unwrap_or_default(),
            ),
            "PING" => Command::Ping(trailing.or_else(|| params.get(0).cloned()).unwrap_or_default()),
            "PONG" => Command::Pong(trailing.or_else(|| params.get(0).cloned()).unwrap_or_default()),
            "QUIT" => Command::Quit(trailing),
            "TOPIC" => Command::Topic(
                params.get(0).cloned().unwrap_or_default(),
                trailing,
            ),
            "NAMES" => Command::Names(
                params.get(0).map(|s| s.split(',').map(String::from).collect()).unwrap_or_default()
            ),
            "LIST" => Command::List(
                params.get(0).map(|s| s.split(',').map(String::from).collect())
            ),
            "MODE" => Command::Mode(
                params.get(0).cloned().unwrap_or_default(),
                params.get(1).cloned().or(trailing),
            ),
            "WHO" => Command::Who(params.get(0).cloned().unwrap_or_default()),
            "WHOIS" => Command::Whois(params.get(0).cloned().unwrap_or_default()),
            "MOTD" => Command::Motd,
            "KICK" => Command::Kick(
                params.get(0).cloned().unwrap_or_default(),
                params.get(1).cloned().unwrap_or_default(),
                trailing,
            ),
            _ => Command::Raw(cmd, params),
        })
    }
}

// detect if this looks like IRC protocol
pub fn is_irc(line: &str) -> bool {
    let irc_commands = [
        "NICK", "USER", "PASS", "CAP", "PING", "PONG",
        "JOIN", "PRIVMSG", "NOTICE", "QUIT",
    ];
    
    let line_upper = line.to_uppercase();
    irc_commands.iter().any(|cmd| {
        line_upper.starts_with(cmd) || line_upper.contains(&format!(" {} ", cmd))
    })
}

// irc server state
pub struct IrcServer {
    clients: Arc<RwLock<HashMap<String, ClientInfo>>>,
    channels: Arc<RwLock<HashMap<String, Channel>>>,
}

#[derive(Clone)]
struct ClientInfo {
    nick: String,
    user: Option<String>,
    realname: Option<String>,
    peer_id: String,
    addr: std::net::SocketAddr,
}

struct Channel {
    name: String,
    topic: Option<String>,
    members: HashSet<String>,  // client ids
}

impl IrcServer {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    // format IRC response
    pub async fn handle_command(
        &self,
        client_id: &str,
        peer_id: &str,
        addr: std::net::SocketAddr,
        cmd: Command,
    ) -> Vec<String> {
        let mut responses = Vec::new();
        
        match cmd {
            Command::Nick(nick) => {
                // register/update client
                let mut clients = self.clients.write().await;
                if let Some(client) = clients.get_mut(client_id) {
                    client.nick = nick.clone();
                } else {
                    clients.insert(client_id.to_string(), ClientInfo {
                        nick: nick.clone(),
                        user: None,
                        realname: None,
                        peer_id: peer_id.to_string(),
                        addr,
                    });
                }
                // send welcome if USER also set
                if clients[client_id].user.is_some() {
                    responses.push(format!(":quicnet 001 {} :Welcome to quicnet IRC", nick));
                    responses.push(format!(":quicnet 002 {} :Your peer id is {}", nick, peer_id));
                    responses.push(format!(":quicnet 003 {} :This server was created just for you", nick));
                    responses.push(format!(":quicnet 004 {} quicnet quicnet-1.0 o o", nick));
                }
            },
            
            Command::User(user, _mode, _unused, realname) => {
                let mut clients = self.clients.write().await;
                if let Some(client) = clients.get_mut(client_id) {
                    client.user = Some(user);
                    client.realname = Some(realname);
                    
                    // send welcome if NICK also set
                    if !client.nick.is_empty() {
                        let nick = client.nick.clone();
                        responses.push(format!(":quicnet 001 {} :Welcome to quicnet IRC", nick));
                        responses.push(format!(":quicnet 002 {} :Your peer id is {}", nick, peer_id));
                        responses.push(format!(":quicnet 003 {} :This server was created just for you", nick));
                        responses.push(format!(":quicnet 004 {} quicnet quicnet-1.0 o o", nick));
                    }
                }
            },
            
            Command::Ping(token) => {
                responses.push(format!(":quicnet PONG quicnet :{}", token));
            },
            
            Command::Join(channels) => {
                let clients = self.clients.read().await;
                if let Some(client) = clients.get(client_id) {
                    let nick = &client.nick;
                    let mut all_channels = self.channels.write().await;
                    
                    for chan_name in channels {
                        // create channel if needed
                        let channel = all_channels.entry(chan_name.clone()).or_insert_with(|| {
                            Channel {
                                name: chan_name.clone(),
                                topic: None,
                                members: HashSet::new(),
                            }
                        });
                        
                        channel.members.insert(client_id.to_string());
                        
                        // send join confirmation
                        responses.push(format!(":{}!{}@{} JOIN {}", 
                            nick, 
                            client.user.as_deref().unwrap_or("user"),
                            peer_id,
                            chan_name
                        ));
                        
                        // send topic if set
                        if let Some(topic) = &channel.topic {
                            responses.push(format!(":quicnet 332 {} {} :{}", nick, chan_name, topic));
                        }
                        
                        // send names list
                        let mut names = Vec::new();
                        for member_id in &channel.members {
                            if let Some(member) = clients.get(member_id) {
                                names.push(member.nick.clone());
                            }
                        }
                        responses.push(format!(":quicnet 353 {} = {} :{}", 
                            nick, chan_name, names.join(" ")
                        ));
                        responses.push(format!(":quicnet 366 {} {} :End of NAMES list", nick, chan_name));
                    }
                }
            },
            
            Command::Privmsg(target, message) => {
                let clients = self.clients.read().await;
                if let Some(sender) = clients.get(client_id) {
                    if target.starts_with('#') {
                        // channel message - would broadcast to all members
                        // for now just echo back
                        responses.push(format!(":{}!{}@{} PRIVMSG {} :{}", 
                            sender.nick,
                            sender.user.as_deref().unwrap_or("user"),
                            peer_id,
                            target,
                            message
                        ));
                    } else {
                        // private message - would forward to target
                        // for now just acknowledge
                        responses.push(format!(":quicnet 401 {} {} :No such nick/channel", 
                            sender.nick, target
                        ));
                    }
                }
            },
            
            Command::Motd => {
                let clients = self.clients.read().await;
                if let Some(client) = clients.get(client_id) {
                    responses.push(format!(":quicnet 375 {} :- quicnet Message of the day -", client.nick));
                    responses.push(format!(":quicnet 372 {} :- Welcome to quicnet IRC bridge", client.nick));
                    responses.push(format!(":quicnet 372 {} :- Your peer id: {}", client.nick, peer_id));
                    responses.push(format!(":quicnet 372 {} :- This is a peer-to-peer network", client.nick));
                    responses.push(format!(":quicnet 376 {} :End of MOTD command", client.nick));
                }
            },
            
            Command::List(_) => {
                let clients = self.clients.read().await;
                if let Some(client) = clients.get(client_id) {
                    let channels = self.channels.read().await;
                    responses.push(format!(":quicnet 321 {} Channel :Users Name", client.nick));
                    for (name, channel) in channels.iter() {
                        responses.push(format!(":quicnet 322 {} {} {} :{}", 
                            client.nick, 
                            name, 
                            channel.members.len(),
                            channel.topic.as_deref().unwrap_or("")
                        ));
                    }
                    responses.push(format!(":quicnet 323 {} :End of LIST", client.nick));
                }
            },
            
            Command::Quit(msg) => {
                // remove from all channels
                let mut channels = self.channels.write().await;
                for channel in channels.values_mut() {
                    channel.members.remove(client_id);
                }
                
                // remove client
                self.clients.write().await.remove(client_id);
                
                // send quit message
                let quit_msg = msg.unwrap_or_else(|| "Client quit".to_string());
                responses.push(format!("ERROR :Closing Link: {} ({})", addr, quit_msg));
            },
            
            _ => {
                // unimplemented command
                let clients = self.clients.read().await;
                if let Some(client) = clients.get(client_id) {
                    responses.push(format!(":quicnet 421 {} {:?} :Unknown command", client.nick, cmd));
                }
            },
        }
        
        responses
    }
}
