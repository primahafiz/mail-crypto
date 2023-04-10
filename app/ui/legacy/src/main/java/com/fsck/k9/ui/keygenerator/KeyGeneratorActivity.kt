package com.fsck.k9.ui.keygenerator
import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.EditText
import android.widget.TextView
import androidx.navigation.ui.AppBarConfiguration
import com.fsck.k9.crypto.ecdsa.KeyPair
import com.fsck.k9.crypto.ecdsa.Secp256k1
import com.fsck.k9.ui.R
import com.fsck.k9.ui.base.K9Activity
import java.math.BigInteger

class KeyGeneratorActivity : K9Activity() {
    private lateinit var publicKeyView : TextView
    private lateinit var privateKeyInput : EditText
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setLayout(R.layout.activity_keygenerator)

        publicKeyView = findViewById(R.id.public_key)
        privateKeyInput = findViewById(R.id.private_key)

        initializeActionBar()
    }

    private fun initializeActionBar() {
        // Empty set of top level destinations so the app bar's "up" button is also displayed at the start destination
        val appBarConfiguration = AppBarConfiguration(topLevelDestinationIds = emptySet())

//        navController = findNavController(R.id.nav_host_fragment)
//        setupActionBarWithNavController(navController, appBarConfiguration)
    }

    override fun onSupportNavigateUp(): Boolean {
        return super.onSupportNavigateUp() || navigateUpBySimulatedBackButtonPress()
    }

    private fun navigateUpBySimulatedBackButtonPress(): Boolean {
        onBackPressed()
        return true
    }
    fun submitbuttonHandler(view: View?) {
        //Decide what happens when the user clicks the submit button
        val SK = BigInteger(privateKeyInput.text.toString())
        val keyPair = KeyPair.generate(SK, Secp256k1)
        publicKeyView.setText(keyPair.publicKey.toString())
    }

    companion object {
        @JvmStatic
        fun launch(activity: Activity) {
            val intent = Intent(activity, KeyGeneratorActivity::class.java)
            activity.startActivity(intent)
        }
    }
}
