from flask import Flask, request, jsonify
import joblib
import numpy as np
from scipy.sparse import hstack, csr_matrix

clf_lr = joblib.load("logistic_password_model.pkl")
vectorizer = joblib.load("tfidf_vectorizer.pkl")
scaler = joblib.load("scaler_len.pkl")

# Map labels -> texte (ajuste si tes labels signifient autre chose)
LABEL_MAP = {
    0: "très_faible",
    1: "faible",
    2: "moyen",
    3: "fort"
}

app = Flask(__name__)

def prepare_features(passwords):
    # passwords : list[str]
    # 1) TF-IDF vectorization (attend une liste de strings)
    X_tfidf = vectorizer.transform(passwords)  # sparse matrix

    # 2) longueur puis scaling (scaler doit être compatible)
    lengths = np.array([len(pw) for pw in passwords]).reshape(-1, 1)
    lengths_scaled = scaler.transform(lengths)  # shape (n,1)

    # 3) combiner tfidf + longueur scalée
    X_combined = hstack([X_tfidf, csr_matrix(lengths_scaled)])
    return X_combined

@app.route("/predict", methods=["POST"])
def predict():
    payload = request.get_json(force=True)
    # accepter soit {"password": "abc"} soit {"passwords": ["a","b"]}
    if "password" in payload:
        pw_list = [payload["password"]]
    elif "passwords" in payload:
        pw_list = payload["passwords"]
    else:
        return jsonify({"error": "Il faut fournir 'password' ou 'passwords'"}), 400

    try:
        print("🔹 Mot de passe reçu :", pw_list)
        X = prepare_features(pw_list)
        preds = clf_lr.predict(X)  # array d'entiers
        preds = [int(p) for p in preds]
        strengths = [LABEL_MAP.get(p, "inconnu") for p in preds]
        return jsonify({"labels": preds, "strengths": strengths})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
