package com.fsck.k9.ui.settings.import

import android.annotation.SuppressLint
import android.app.Activity
import android.app.Dialog
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.widget.CheckBox
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.constraintlayout.widget.Group
import androidx.core.os.bundleOf
import androidx.core.view.isGone
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.Fragment
import com.fsck.k9.ui.R

class PasswordPromptDialogFragment : DialogFragment() {
    private lateinit var accountUuid: String
    private var inputOutgoingServerPassword: Boolean = false
    private var inputIncomingServerPassword: Boolean = false

    private lateinit var dialogView: View

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val arguments = this.arguments ?: error("Fragment arguments missing")

        accountUuid = arguments.getString(ARG_ACCOUNT_UUID) ?: error("Missing account UUID")
        val accountName = arguments.getString(ARG_ACCOUNT_NAME) ?: error("Missing account name")
        val incomingServerName = arguments.getString(ARG_INCOMING_SERVER_NAME)
        val outgoingServerName = arguments.getString(ARG_OUTGOING_SERVER_NAME)

        inputIncomingServerPassword = arguments.getBoolean(ARG_INPUT_INCOMING_SERVER_PASSWORD)
        inputOutgoingServerPassword = arguments.getBoolean(ARG_INPUT_OUTGOING_SERVER_PASSWORD)
        if (!inputIncomingServerPassword && !inputOutgoingServerPassword) {
            error("Not prompting for any password")
        }

        dialogView = createView(
            accountName,
            inputIncomingServerPassword,
            incomingServerName,
            inputOutgoingServerPassword,
            outgoingServerName,
        )

        return AlertDialog.Builder(requireContext())
            .setView(dialogView)
            .setPositiveButton(R.string.okay_action) { _, _ -> deliverPasswordPromptResult() }
            .setNegativeButton(R.string.cancel_action, null)
            .create()
    }

    @SuppressLint("InflateParams")
    private fun createView(
        accountName: String,
        inputIncomingServerPassword: Boolean,
        incomingServerName: String?,
        inputOutgoingServerPassword: Boolean,
        outgoingServerName: String?,
    ): View {
        val layoutInflater = LayoutInflater.from(requireContext())
        val view = layoutInflater.inflate(R.layout.password_prompt_dialog, null)

        val passwordPromptIntro: TextView = view.findViewById(R.id.passwordPromptIntro)
        val incomingServerNameView: TextView = view.findViewById(R.id.incomingServerName)
        val outgoingServerNameView: TextView = view.findViewById(R.id.outgoingServerName)
        val useSamePasswordCheckbox: CheckBox = view.findViewById(R.id.useSamePasswordCheckbox)
        val incomingServerGroup: Group = view.findViewById(R.id.incomingServerGroup)
        val outgoingServerGroup: Group = view.findViewById(R.id.outgoingServerGroup)

        val quantity = if (inputIncomingServerPassword && inputOutgoingServerPassword) 2 else 1
        passwordPromptIntro.text = resources.getQuantityString(
            R.plurals.settings_import_password_prompt,
            quantity,
            accountName,
        )
        incomingServerNameView.text = getString(R.string.server_name_format, incomingServerName)
        outgoingServerNameView.text = getString(R.string.server_name_format, outgoingServerName)

        incomingServerGroup.isGone = !inputIncomingServerPassword
        outgoingServerGroup.isGone = !inputOutgoingServerPassword

        if (inputIncomingServerPassword && inputOutgoingServerPassword) {
            useSamePasswordCheckbox.isChecked = true
            outgoingServerGroup.isGone = true

            useSamePasswordCheckbox.setOnCheckedChangeListener { _, isChecked ->
                outgoingServerGroup.isGone = isChecked
            }
        } else {
            useSamePasswordCheckbox.isGone = true
        }

        return view
    }

    private fun deliverPasswordPromptResult() {
        val incomingServerPasswordView: TextView = dialogView.findViewById(R.id.incomingServerPassword)
        val outgoingServerPasswordView: TextView = dialogView.findViewById(R.id.outgoingServerPassword)
        val useSamePasswordCheckbox: CheckBox = dialogView.findViewById(R.id.useSamePasswordCheckbox)

        val incomingServerPassword = when {
            !inputIncomingServerPassword -> null
            else -> incomingServerPasswordView.text.toString()
        }
        val outgoingServerPassword = when {
            !inputOutgoingServerPassword -> null
            useSamePasswordCheckbox.isChecked -> incomingServerPassword
            else -> outgoingServerPasswordView.text.toString()
        }

        val resultIntent = PasswordPromptResult(accountUuid, incomingServerPassword, outgoingServerPassword).asIntent()

        targetFragment!!.onActivityResult(targetRequestCode, Activity.RESULT_OK, resultIntent)
    }

    companion object {
        private const val ARG_ACCOUNT_UUID = "accountUuid"
        private const val ARG_ACCOUNT_NAME = "accountName"
        private const val ARG_INPUT_INCOMING_SERVER_PASSWORD = "inputIncomingServerPassword"
        private const val ARG_INCOMING_SERVER_NAME = "incomingServerName"
        private const val ARG_INPUT_OUTGOING_SERVER_PASSWORD = "inputOutgoingServerPassword"
        private const val ARG_OUTGOING_SERVER_NAME = "outgoingServerName"

        fun create(
            accountUuid: String,
            accountName: String,
            inputIncomingServerPassword: Boolean,
            incomingServerName: String?,
            inputOutgoingServerPassword: Boolean,
            outgoingServerName: String?,
            targetFragment: Fragment,
            requestCode: Int,
        ) = PasswordPromptDialogFragment().apply {
            arguments = bundleOf(
                ARG_ACCOUNT_UUID to accountUuid,
                ARG_ACCOUNT_NAME to accountName,
                ARG_INPUT_INCOMING_SERVER_PASSWORD to inputIncomingServerPassword,
                ARG_INCOMING_SERVER_NAME to incomingServerName,
                ARG_INPUT_OUTGOING_SERVER_PASSWORD to inputOutgoingServerPassword,
                ARG_OUTGOING_SERVER_NAME to outgoingServerName,
            )
            setTargetFragment(targetFragment, requestCode)
        }
    }
}
