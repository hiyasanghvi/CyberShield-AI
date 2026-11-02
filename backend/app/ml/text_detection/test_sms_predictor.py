from app.ml.text_detection.sms_predictor import predict_sms


test_messages = [

    "Congratulations! You have won a free prize. Call now to claim.",

    "URGENT! Your account has been selected for a cash reward. Click now.",

    "Hey, are we meeting at college tomorrow?",

    "Can you send me the notes from today's lecture?",

]


for message in test_messages:

    result = predict_sms(message)

    print("\n" + "=" * 60)

    print("SMS:")
    print(message)

    print(
        "Classification:",
        result["classification"]
    )

    print(
        "Spam probability:",
        round(
            result["spam_probability"],
            4
        )
    )

    print(
        "HAM probability:",
        round(
            result["ham_probability"],
            4
        )
    )

    print(
        "Confidence:",
        round(
            result["confidence"],
            4
        )
    )