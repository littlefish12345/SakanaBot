package SakanaBot

func (qqClient *QQClient) FindFriend(uin int64) (bool, string) {
	if uin == qqClient.Uin {
		return true, qqClient.NickName
	}
	for _, friend := range qqClient.FriendList {
		if friend.FriendUin == uin {
			return true, friend.NickName
		}
	}
	return false, ""
}
