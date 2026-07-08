package com.aivpn.client

import android.graphics.Typeface
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.aivpn.client.databinding.ItemProfileBinding

class ProfilesAdapter(
    private val onProfileClick: (SecureStorage.ConnectionProfile) -> Unit,
    private val onEditClick:    (SecureStorage.ConnectionProfile) -> Unit,
    private val onDeleteClick:  (SecureStorage.ConnectionProfile) -> Unit,
) : ListAdapter<SecureStorage.ConnectionProfile, ProfilesAdapter.ViewHolder>(DIFF_CALLBACK) {

    var activeProfileId: String? = null
        set(value) {
            field = value
            notifyItemRangeChanged(0, itemCount)
        }
    var editingEnabled: Boolean = true

    inner class ViewHolder(val binding: ItemProfileBinding) :
        RecyclerView.ViewHolder(binding.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = ItemProfileBinding.inflate(
            LayoutInflater.from(parent.context), parent, false
        )
        return ViewHolder(binding)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val profile = getItem(position)
        val isActive = profile.id == activeProfileId
        with(holder.binding) {
            profileName.text   = profile.name
            profileServer.text = ConnectionKeyParser.serverAddrFrom(profile.key)
            profileName.setTypeface(
                null,
                if (isActive) Typeface.BOLD else Typeface.NORMAL
            )
            root.setOnClickListener { onProfileClick(profile) }
            val editVis = if (editingEnabled) android.view.View.VISIBLE else android.view.View.GONE
            btnEdit.visibility   = editVis
            btnDelete.visibility = editVis
            btnEdit.setOnClickListener   { onEditClick(profile) }
            btnDelete.setOnClickListener { onDeleteClick(profile) }
        }
    }

    companion object {
        val DIFF_CALLBACK = object : DiffUtil.ItemCallback<SecureStorage.ConnectionProfile>() {
            override fun areItemsTheSame(
                a: SecureStorage.ConnectionProfile,
                b: SecureStorage.ConnectionProfile,
            ) = a.id == b.id

            override fun areContentsTheSame(
                a: SecureStorage.ConnectionProfile,
                b: SecureStorage.ConnectionProfile,
            ) = a == b
        }
    }
}
