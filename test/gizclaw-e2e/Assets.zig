pub const doubao_realtime_workspace_config_json = @embedFile("client/chat/config/doubao-realtime.example.json");

pub const ChatAudioAsset = struct {
    name: []const u8,
    ogg_opus: []const u8,
};

pub const chat_round_01 = ChatAudioAsset{
    .name = "round-01.ogg",
    .ogg_opus = @embedFile("testdata/chat/roundtrip/round-01.ogg"),
};

pub const chat_round_02 = ChatAudioAsset{
    .name = "round-02.ogg",
    .ogg_opus = @embedFile("testdata/chat/roundtrip/round-02.ogg"),
};

pub const chat_round_03 = ChatAudioAsset{
    .name = "round-03.ogg",
    .ogg_opus = @embedFile("testdata/chat/roundtrip/round-03.ogg"),
};
