package com.example.myapplication;

import android.content.Context;
import android.security.identity.*;


public class store {

    public store(){
        Context c = new ccc();
        IdentityCredentialStore ics = IdentityCredentialStore.getDirectAccessInstance(c);
        System.out.println(ics);
//        WritableIdentityCredential wc
//        ics.createCredential("ffff","String");
//        System.out.println();
//        String[] ss = ics.getSupportedDocTypes();
    }



//    @Override
//    public int hashCode() {
//        return super.hashCode();
//    }
//
//    @NonNull
//    @Override
//    public String toString() {
//        return super.toString();
//    }
}
