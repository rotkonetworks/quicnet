use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ChannelType {
    Shell,
    Exec(String),
    Forward { host: String, port: u16 },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ControlMsg {
    Resize { rows: u16, cols: u16 },
    Exit(i32),
    Signal(i32),
    ChannelOpen(ChannelType),
}
