package com.fsck.k9.message

import com.fsck.k9.Account
import com.fsck.k9.helper.ReplyToParser
import com.fsck.k9.mail.Message

/**
 * Figures out which reply actions are available to the user.
 */
class ReplyActionStrategy(private val replyRoParser: ReplyToParser) {
    fun getReplyActions(account: Account, message: Message): ReplyActions {
        val recipientsToReplyTo = replyRoParser.getRecipientsToReplyTo(message, account)
        val recipientsToReplyAllTo = replyRoParser.getRecipientsToReplyAllTo(message, account)

        val replyToAllCount = recipientsToReplyAllTo.to.size + recipientsToReplyAllTo.cc.size
        return if (replyToAllCount <= 1) {
            if (recipientsToReplyTo.to.isEmpty()) {
                ReplyActions(defaultAction = null)
            } else {
                ReplyActions(defaultAction = ReplyAction.REPLY)
            }
        } else {
            ReplyActions(defaultAction = ReplyAction.REPLY_ALL, additionalActions = listOf(ReplyAction.REPLY))
        }
    }
}

data class ReplyActions(
    val defaultAction: ReplyAction?,
    val additionalActions: List<ReplyAction> = emptyList(),
)

enum class ReplyAction {
    REPLY,
    REPLY_ALL,
}
